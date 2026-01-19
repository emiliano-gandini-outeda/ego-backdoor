# ego-backdoor
 Private admin-style FastAPI app for secure file browsing and management. Authenticated access only.

## Features

- Login-protected dashboard
- Browse files on the server
- Download files from a secure directory
- Minimal and clean interface
- Uses FastAPI + Jinja2 + SQLite for user management

## Security

- Passwords are hashed using bcrypt
- All routes (except `/login`) require authentication
- Prevents path traversal and unauthorized access
- Intended for private, non-public use