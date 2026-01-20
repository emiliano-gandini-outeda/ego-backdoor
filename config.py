import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Database
DATABASE_URL = "sqlite:///./users.db"

# File system
BASE_FILES_DIR = Path("/var/www/backdoor/files")
# For development, use a local directory
if not BASE_FILES_DIR.exists():
    BASE_FILES_DIR = BASE_DIR / "files"
    BASE_FILES_DIR.mkdir(exist_ok=True)

MAX_FILE_SIZE = 1024 * 1024 * 1024 * 10 # 10GB

# Allowed file extensions for preview
TEXT_EXTENSIONS = {'.txt', '.py', '.js', '.html', '.css', '.json', '.xml', '.csv', 
                   '.md', '.sh', '.bash', '.yml', '.yaml', '.ini', '.cfg', '.conf'}
IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp'}
CODE_EXTENSIONS = {'.py', '.js', '.html', '.css', '.java', '.cpp', '.c', '.php', 
                   '.rb', '.go', '.rs', '.ts'}
PDF_EXTENSIONS = {'.pdf'}
DOC_EXTENSIONS = {'.doc', '.docx', '.odt'}