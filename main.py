from fastapi import FastAPI, Request, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pathlib import Path
import shutil
import aiofiles
import magic
import mimetypes
from PIL import Image
import io
import base64
from typing import Optional
from pydantic import BaseModel
from jose import jwt, JWTError

from auth import (
    authenticate_user, 
    create_access_token, 
    User,
)
from dependencies import get_db, get_current_user
from config import (
    BASE_FILES_DIR, 
    MAX_FILE_SIZE, 
    TEXT_EXTENSIONS, 
    IMAGE_EXTENSIONS,
    CODE_EXTENSIONS,
    PDF_EXTENSIONS,
    DOC_EXTENSIONS,
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from datetime import timedelta
import uuid

# Initialize FastAPI
app = FastAPI(title="Backdoor Admin", debug=False)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# Session middleware (simplified version)
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.sessions import SessionMiddleware

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=3600)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["backdoor.ego-services.com", "localhost", "127.0.0.1"])

# Ensure base directories exist
BASE_FILES_DIR.mkdir(parents=True, exist_ok=True)

# Pydantic models for login
class LoginForm(BaseModel):
    username: str
    password: str

# Utility functions
def sanitize_path(user_path: str) -> Path:
    """Sanitize and validate file paths to prevent directory traversal."""
    if not user_path or user_path == ".":
        return BASE_FILES_DIR
    
    # Clean the path
    try:
        # Handle relative paths
        if user_path.startswith('.'):
            clean_path = (BASE_FILES_DIR / user_path).resolve()
        else:
            clean_path = (BASE_FILES_DIR / user_path).resolve()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid path")
    
    # Ensure the path is within BASE_FILES_DIR
    try:
        clean_path.relative_to(BASE_FILES_DIR)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid path")
    
    return clean_path

def get_file_info(file_path: Path):
    """Get file information for display."""
    try:
        stat = file_path.stat()
        # Get modification time in milliseconds for JavaScript
        modified_ms = int(stat.st_mtime * 1000)
        
        # Check if it's a directory (explicitly use is_dir())
        is_dir = file_path.is_dir()
        
        # Extension
        extension = file_path.suffix.lower() if not is_dir else ""

        # Debug logging
        print(f"File info: {file_path.name}, is_dir: {is_dir}, size: {stat.st_size}, path: {file_path}, Extenion: {extension}")
        
        return {
            "name": file_path.name,
            "path": str(file_path.relative_to(BASE_FILES_DIR)),
            "size": stat.st_size,
            "modified": modified_ms,
            "is_dir": is_dir,  # Boolean value
            "extension": extension,
            "mime_type": mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        }
    except Exception as e:
        print(f"Error getting file info for {file_path}: {e}")
        is_dir = file_path.is_dir() if file_path.exists() else False
        return {
            "name": file_path.name,
            "path": str(file_path.relative_to(BASE_FILES_DIR)),
            "size": 0,
            "modified": 0,
            "is_dir": is_dir,  # Boolean value
            "extension": file_path.suffix.lower() if not is_dir else "",
            "mime_type": "application/octet-stream"
        }

def get_directory_listing(path: Path):
    """Get listing of files and directories."""
    items = []
    
    try:
        if path.exists() and path.is_dir():
            for item in path.iterdir():
                # Skip hidden files
                if item.name.startswith('.'):
                    continue
                    
                try:
                    items.append(get_file_info(item))
                except OSError:
                    continue
        
        # Sort: directories first, then files, both alphabetically
        items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        return items
    except Exception as e:
        print(f"Error reading directory {path}: {e}")
        return []

async def get_file_preview(file_path: Path, max_size: int = 1024 * 1024):
    """Generate preview for different file types."""
    if not file_path.exists() or file_path.is_dir():
        return None
    
    file_size = file_path.stat().st_size
    extension = file_path.suffix.lower()
    
    preview = {
        "type": "unknown",
        "content": None,
        "size": file_size,
        "truncated": False
    }
    
    try:
        # Text files
        if extension in TEXT_EXTENSIONS or extension in CODE_EXTENSIONS:
            preview["type"] = "text"
            try:
                async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                    content = await f.read(max_size)
                    preview["content"] = content
                    if file_size > max_size:
                        preview["truncated"] = True
            except:
                try:
                    async with aiofiles.open(file_path, 'rb') as f:
                        content = await f.read(max_size)
                        preview["content"] = content.decode('latin-1', errors='ignore')
                        if file_size > max_size:
                            preview["truncated"] = True
                except:
                    preview["content"] = "Unable to read file content"
        
        # Images
        elif extension in IMAGE_EXTENSIONS:
            preview["type"] = "image"
            if extension == '.svg':
                # Read SVG as text and embed directly
                async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                    svg_content = await f.read(min(file_size, max_size))
                    # Clean up SVG for safe embedding
                    svg_content = svg_content.replace('<script', '<!-- script').replace('</script>', '-->')
                    preview["content"] = svg_content
                    if file_size > max_size:
                        preview["truncated"] = True
            else:
                # Convert image to base64 for preview
                try:
                    img = Image.open(file_path)
                    
                    # Calculate dimensions to fit preview
                    max_preview_size = 800
                    width, height = img.size
                    
                    if width > max_preview_size or height > max_preview_size:
                        ratio = min(max_preview_size / width, max_preview_size / height)
                        new_width = int(width * ratio)
                        new_height = int(height * ratio)
                        img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
                    
                    buffered = io.BytesIO()
                    
                    if img.mode in ('RGBA', 'LA') or (img.mode == 'P' and 'transparency' in img.info):
                        img = img.convert('RGBA')
                        img.save(buffered, format="PNG")
                        mime_type = "image/png"
                    else:
                        img = img.convert('RGB')
                        img.save(buffered, format="JPEG", quality=85)
                        mime_type = "image/jpeg"
                    
                    preview["content"] = f"data:{mime_type};base64," + base64.b64encode(buffered.getvalue()).decode()
                except Exception as e:
                    preview["content"] = f"Unable to preview image: {str(e)}"
        
        # PDF files (just show info)
        elif extension in PDF_EXTENSIONS:
            preview["type"] = "pdf"
            preview["content"] = f"PDF file - {file_size:,} bytes"
        
        # Document files
        elif extension in DOC_EXTENSIONS:
            preview["type"] = "document"
            preview["content"] = f"Document file - {file_size:,} bytes"
        
        # Binary files
        else:
            preview["type"] = "binary"
            try:
                mime_type = magic.from_file(str(file_path), mime=True)
                preview["content"] = f"Binary file ({mime_type}) - {file_size:,} bytes"
            except:
                preview["content"] = f"Binary file - {file_size:,} bytes"
    
    except Exception as e:
        preview["content"] = f"Error generating preview: {str(e)}"
    
    return preview

# Routes
@app.get("/", response_class=HTMLResponse)
async def root(request: Request, db: Session = Depends(get_db)):
    """Root redirects to dashboard or login."""
    # Check if user has a valid token in session
    if "access_token" in request.session:
        try:
            # Verify the token is still valid
            token = request.session["access_token"]
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username:
                # Token is valid, redirect to dashboard
                return RedirectResponse(url="/dashboard")
        except JWTError:
            # Token is invalid/expired, clear session
            request.session.clear()
    
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, db: Session = Depends(get_db)):
    """Login page."""
    # Check if user has a valid token in session
    if "access_token" in request.session:
        try:
            # Verify the token is still valid
            token = request.session["access_token"]
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username:
                # Token is valid, redirect to dashboard
                return RedirectResponse(url="/dashboard")
        except JWTError:
            # Token is invalid/expired, clear session and show login
            request.session.clear()
    
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Handle login."""
    user = authenticate_user(db, username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    # Store token in session
    request.session["access_token"] = access_token
    request.session["username"] = user.username
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/logout")
async def logout(request: Request):
    """Handle logout."""
    request.session.clear()
    return RedirectResponse(url="/login")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    path: str = "",
):
    """Main dashboard with file browser."""
    # Check authentication manually instead of using dependency
    if "access_token" not in request.session:
        return RedirectResponse(url="/login")
    
    # Verify the token is valid
    try:
        token = request.session["access_token"]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if not username:
            # Invalid token, redirect to login
            request.session.clear()
            return RedirectResponse(url="/login")
    
    except JWTError:
        # Token invalid/expired, clear session and redirect to login
        request.session.clear()
        return RedirectResponse(url="/login")
    
    safe_path = sanitize_path(path)
    
    # Get directory listing
    items = get_directory_listing(safe_path)
    
    # Get parent directory if not at root
    parent_path = None
    if safe_path != BASE_FILES_DIR:
        parent_path = str(safe_path.parent.relative_to(BASE_FILES_DIR))
    
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "items": items,
            "current_path": str(safe_path.relative_to(BASE_FILES_DIR)),
            "parent_path": parent_path,
            "username": username
        }
    )

@app.get("/api/files")
async def list_files(
    path: str = "",
):
    """API endpoint for file listing."""
    safe_path = sanitize_path(path)
    
    if not safe_path.exists() or not safe_path.is_dir():
        raise HTTPException(status_code=404, detail="Directory not found")
    
    items = get_directory_listing(safe_path)
    return {"items": items, "current_path": str(safe_path.relative_to(BASE_FILES_DIR))}

@app.get("/api/preview")
async def preview_file(
    path: str,
):
    """API endpoint for file preview."""
    safe_path = sanitize_path(path)
    
    if not safe_path.exists() or safe_path.is_dir():
        raise HTTPException(status_code=404, detail="File not found")
    
    preview = await get_file_preview(safe_path)
    file_info = get_file_info(safe_path)
    
    return {
        "preview": preview,
        "file_info": file_info
    }

@app.get("/download")
async def download_file(
    path: str,
):
    """Download a file."""
    safe_path = sanitize_path(path)
    
    if not safe_path.exists() or safe_path.is_dir():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        path=safe_path,
        filename=safe_path.name,
        media_type='application/octet-stream'
    )

@app.post("/api/upload")
async def upload_file(
    path: str = Form(""),
    file: UploadFile = File(...),
):
    """Upload a file."""
    safe_path = sanitize_path(path)
    
    if not safe_path.is_dir():
        raise HTTPException(status_code=400, detail="Path is not a directory")
    
    temp_path = safe_path / f"temp_{uuid.uuid4()}"
    file_size = 0
    
    try:
        # Write file in chunks
        async with aiofiles.open(temp_path, 'wb') as f:
            chunk_size = 8192 * 1024  # 8MB chunks for better performance
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(status_code=400, detail="File too large (max 10GB)")
                await f.write(chunk)
        
        # Move to final location
        final_path = safe_path / file.filename
        
        # Check if file exists
        if final_path.exists():
            raise HTTPException(status_code=400, detail="File already exists")
        
        shutil.move(str(temp_path), str(final_path))
        
        return {
            "success": True,
            "message": f"File '{file.filename}' uploaded successfully",
            "file_info": get_file_info(final_path)
        }
    
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/delete")
async def delete_file(
    path: str,
):
    """Delete a file or directory."""
    safe_path = sanitize_path(path)
    
    if not safe_path.exists():
        raise HTTPException(status_code=404, detail="File or directory not found")
    
    # Prevent deletion of base directory
    if safe_path == BASE_FILES_DIR:
        raise HTTPException(status_code=400, detail="Cannot delete base directory")
    
    try:
        if safe_path.is_dir():
            shutil.rmtree(safe_path)
            message = "Directory deleted successfully"
        else:
            safe_path.unlink()
            message = "File deleted successfully"
        
        return {"success": True, "message": message}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/create-folder")
async def create_folder(
    path: str = Form(""),
    folder_name: str = Form(...),
):
    """Create a new folder."""
    safe_path = sanitize_path(path)
    
    if not safe_path.is_dir():
        raise HTTPException(status_code=400, detail="Path is not a directory")
    
    # Validate folder name
    if not folder_name or folder_name.startswith('.') or '/' in folder_name:
        raise HTTPException(status_code=400, detail="Invalid folder name")
    
    new_folder = safe_path / folder_name
    
    if new_folder.exists():
        raise HTTPException(status_code=400, detail="Folder already exists")
    
    try:
        new_folder.mkdir()
        return {
            "success": True,
            "message": f"Folder '{folder_name}' created successfully",
            "folder_info": get_file_info(new_folder)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/folders-tree")
async def list_folders_tree(
    exclude: str = "",
):
    """Get nested structure of all folders for move operation."""
    
    def build_folder_tree(path: Path, base_path: Path = BASE_FILES_DIR, depth: int = 0):
        """Recursively build folder tree."""
        folders = []
        
        try:
            for item in path.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    # Skip the excluded folder and its children
                    if exclude and str(item.relative_to(base_path)) == exclude:
                        continue
                    
                    # Build folder info
                    folder_info = {
                        "name": item.name,
                        "path": str(item.relative_to(base_path)),
                        "full_path": " / ".join(item.relative_to(base_path).parts),
                        "has_children": False,
                        "children": []
                    }
                    
                    # Check if folder has subfolders (excluding excluded ones)
                    try:
                        subfolders = [subitem for subitem in item.iterdir() 
                                    if subitem.is_dir() 
                                    and not subitem.name.startswith('.')
                                    and not (exclude and str(subitem.relative_to(base_path)) == exclude)]
                        folder_info["has_children"] = len(subfolders) > 0
                    except:
                        folder_info["has_children"] = False
                    
                    # Recursively build children (only if not at max depth to prevent recursion)
                    if depth < 10:  # Safety limit
                        children = build_folder_tree(item, base_path, depth + 1)
                        folder_info["children"] = children
                    
                    folders.append(folder_info)
        except Exception as e:
            print(f"Error building folder tree from {path}: {e}")
        
        # Sort folders alphabetically
        folders.sort(key=lambda x: x["name"].lower())
        return folders
    
    # Get the nested structure
    nested_folders = build_folder_tree(BASE_FILES_DIR)
    
    # Create root folder info
    root_path_str = str(BASE_FILES_DIR.relative_to(BASE_FILES_DIR)) or ""
    
    return [
        {
            "name": "Root",
            "path": root_path_str,
            "full_path": "Root",
            "has_children": len(nested_folders) > 0,
            "children": nested_folders
        }
    ]

@app.post("/api/move")
async def move_item(
    request: Request,
):
    """Move a file or folder."""
    try:
        data = await request.json()
        source_path = data.get("source")
        destination_path = data.get("destination")
        is_dir = data.get("is_dir", False)
        
        if not source_path:
            raise HTTPException(status_code=400, detail="Source path is required")
        
        # Sanitize paths
        source = sanitize_path(source_path)
        destination = sanitize_path(destination_path) if destination_path else BASE_FILES_DIR
        
        # Check if source exists
        if not source.exists():
            raise HTTPException(status_code=404, detail="Source item not found")
        
        # Check if destination is a directory
        if not destination.is_dir():
            raise HTTPException(status_code=400, detail="Destination is not a directory")
        
        # Prevent moving into itself or its children
        if is_dir:
            try:
                destination.relative_to(source)
                raise HTTPException(status_code=400, detail="Cannot move folder into itself or its subfolders")
            except ValueError:
                pass
        
        # Construct new path
        new_path = destination / source.name
        
        # Check if item already exists at destination
        if new_path.exists():
            raise HTTPException(status_code=400, detail="Item with same name already exists at destination")
        
        # Perform the move
        shutil.move(str(source), str(new_path))
        
        return {
            "success": True,
            "message": f"{'Folder' if is_dir else 'File'} moved successfully",
            "new_path": str(new_path.relative_to(BASE_FILES_DIR))
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Move failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)