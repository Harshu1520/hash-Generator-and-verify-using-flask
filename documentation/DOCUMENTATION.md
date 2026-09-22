# File Integrity Verification System
## M.Sc. IT Semester 1 Tiny Project

**Project Type:** Tiny Project  
**Technology:** Python Flask + PostgreSQL  
**Security Technique:** SHA-256 File Integrity Verification

### Abstract
The File Integrity Verification System is a web-based application developed using Python Flask and PostgreSQL. It allows an authenticated user to upload a file, generate its SHA-256 cryptographic hash, store file metadata, and later verify whether the file has changed. The system also maintains an activity log for important operations.

### Objectives
1. Develop a simple Flask web application.
2. Generate SHA-256 hashes for uploaded files.
3. Store file metadata and hashes in PostgreSQL.
4. Verify file integrity by recalculating the hash.
5. Provide authentication and basic audit logging.
6. Organize the project as a professional GitHub repository.

### Modules
- Authentication Module
- File Upload Module
- Hash Generation Module
- File Verification Module
- File Management Module
- Activity Log Module

### Functional Requirements
- User can register and log in.
- User can upload a file.
- System generates SHA-256 hash.
- System stores metadata and hash.
- User can verify file integrity.
- User can download or delete their own files.
- System records activity.

### Non-Functional Requirements
- Usable web interface
- Passwords stored as secure password hashes
- File size limit
- Owner-based access control
- Maintainable project structure

### Database Tables
**users:** id, username, password_hash, created_at  
**file_records:** id, original_filename, stored_filename, file_size, sha256_hash, uploaded_at, owner_id  
**activity_logs:** id, action, details, created_at, user_id

### System Flow
User → Login → Dashboard → Upload File → SHA-256 Generation → Database Storage → Verify → Recalculate Hash → Compare → Result.

### Testing
| Test ID | Test Case | Expected Result |
|---|---|---|
| TC01 | Register valid user | Account created |
| TC02 | Login with correct credentials | Dashboard opens |
| TC03 | Login with wrong password | Error displayed |
| TC04 | Upload valid file | File and SHA-256 stored |
| TC05 | Verify unchanged file | VALID result |
| TC06 | Verify modified file | MODIFIED result |
| TC07 | Download own file | File downloaded |
| TC08 | Delete own file | File removed |
| TC09 | Upload file >16 MB | Rejected |
| TC10 | Access another user's record | Not allowed |

### Future Scope
- Admin dashboard
- Multiple hashing algorithms
- Digital evidence metadata
- Email notifications
- Cloud storage
- Role-based access control
- Deployment with Docker
- Production WSGI server

### Conclusion
The project demonstrates how Flask, PostgreSQL, authentication, file handling, and cryptographic hashing can be combined into a small cybersecurity-oriented web application. SHA-256 provides a reliable mechanism for detecting changes to a file because even a small file modification produces a different digest.

### References
1. Python Documentation — hashlib module.
2. Flask Documentation.
3. Flask-SQLAlchemy Documentation.
4. PostgreSQL Documentation.
5. OWASP Web Application Security guidance.
