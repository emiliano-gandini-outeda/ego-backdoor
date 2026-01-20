import sys
import os
from dotenv import load_dotenv
from auth import SessionLocal, get_password_hash, User
from sqlalchemy.exc import IntegrityError

# Load environment variables
load_dotenv()

def parse_simple_users():
    """Parse simple username:password format from BACKDOOR_USERS."""
    users_str = os.getenv("BACKDOOR_USERS", "").strip()
    
    if not users_str:
        return []
    
    users = []
    for pair in users_str.split(','):
        pair = pair.strip()
        if not pair:
            continue
            
        if ':' not in pair:
            print(f">> Warning: Invalid format '{pair}', expected 'username:password'")
            continue
            
        username, password = pair.split(':', 1)
        username = username.strip()
        password = password.strip()
        
        if username and password:
            users.append({
                "username": username,
                "password": password
            })
        else:
            print(f">> Warning: Skipping empty username or password in '{pair}'")
    
    return users

def create_user_from_env():
    """Create users from environment variables."""
    print("=== Creating Users from Environment ===")
    
    # Parse users in simple format
    users = parse_simple_users()
    
    if not users:
        print(">> No users found in BACKDOOR_USERS environment variable")
        print("Please set BACKDOOR_USERS in your .env file")
        print("Format: username1:password1,username2:password2,...")
        sys.exit(1)
    
    db = SessionLocal()
    created_count = 0
    skipped_count = 0
    
    for user_data in users:
        username = user_data.get("username", "").strip()
        password = user_data.get("password", "").strip()
        
        if not username:
            print(f">> Skipping user with empty username")
            skipped_count += 1
            continue
        
        if not password:
            print(f">> Skipping user '{username}' with empty password")
            skipped_count += 1
            continue
        
        try:
            # Check if user already exists
            existing_user = db.query(User).filter(User.username == username).first()
            if existing_user:
                print(f">> User '{username}' already exists, skipping...")
                skipped_count += 1
                continue
            
            # Create new user
            hashed_password = get_password_hash(password)
            user = User(
                username=username,
                hashed_password=hashed_password,
                is_active=1
            )
            
            db.add(user)
            db.commit()
            print(f">> Created user: {username}")
            created_count += 1
            
        except IntegrityError:
            db.rollback()
            print(f">> User '{username}' already exists, skipping...")
            skipped_count += 1
        except Exception as e:
            db.rollback()
            print(f">> Error creating user '{username}': {e}")
            skipped_count += 1
    
    db.close()
    
    print(f"\n>> Summary:")
    print(f"  Created: {created_count} user(s)")
    print(f"  Skipped: {skipped_count} user(s)")
    
    if created_count > 0:
        print("\n>> Users created successfully!")
    elif skipped_count > 0:
        print("\n>> All users already exist")
    else:
        print("\n>> No users were created")

def create_user_interactive():
    """Create a new user via command line (fallback)."""
    print("=== Create Backdoor Admin User (Interactive) ===")
    
    username = input("Username: ").strip()
    if not username:
        print(">> Username cannot be empty")
        sys.exit(1)
    
    import getpass
    password = getpass.getpass("Password: ")
    if not password:
        print(">> Password cannot be empty")
        sys.exit(1)
    
    confirm_password = getpass.getpass("Confirm password: ")
    if password != confirm_password:
        print(">> Passwords do not match")
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
        
        print(f"\n>> User '{username}' created successfully!")
        
    except IntegrityError:
        db.rollback()
        print(f"\n>> Error: User '{username}' already exists")
        sys.exit(1)
    except Exception as e:
        db.rollback()
        print(f"\n>> Error creating user: {e}")
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    # Check if we should use env or interactive mode
    if os.getenv("BACKDOOR_USERS"):
        create_user_from_env()
    else:
        # Fallback to interactive mode if no env var
        print(">> BACKDOOR_USERS not found in .env file")
        print(">> Example format: eclipse:Isoldayemi1218@,beatriz:Biayemi2105")
        response = input("\n>> Do you want to create a user interactively? (y/N): ").strip().lower()
        if response == 'y':
            create_user_interactive()
        else:
            print("\n>> Add to your .env file:")
            print("BACKDOOR_USERS=username1:password1,username2:password2")
            print("\n>> Then run this script again.")