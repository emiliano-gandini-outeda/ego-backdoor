import sys
import getpass
from auth import SessionLocal, get_password_hash, User
from sqlalchemy.exc import IntegrityError

def create_user():
    """Create a new user via command line."""
    print("=== Create Backdoor Admin User ===")
    
    username = input("Username: ").strip()
    if not username:
        print("Username cannot be empty")
        sys.exit(1)
    
    password = getpass.getpass("Password: ")
    if not password:
        print("Password cannot be empty")
        sys.exit(1)
    
    confirm_password = getpass.getpass("Confirm password: ")
    if password != confirm_password:
        print("Passwords do not match")
        sys.exit(1)
    
    db = SessionLocal()
    try:
        hashed_password = get_password_hash(password)
        
        user = User(
            username=username,
            hashed_password=hashed_password,
            is_active=1
        )
        
        db.add(user)
        db.commit()
        
        print(f"\n✅ User '{username}' created successfully!")
        print("\nYou can now run the application with:")
        print("  uvicorn main:app --host 0.0.0.0 --port 8001")
        
    except IntegrityError:
        db.rollback()
        print(f"\n❌ Error: User '{username}' already exists")
        sys.exit(1)
    except Exception as e:
        db.rollback()
        print(f"\n❌ Error creating user: {e}")
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    create_user()