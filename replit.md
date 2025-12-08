# VPS Manager - Forensic Investigation Tool

## Overview
This is a VPS management platform designed for forensic investigation purposes. It allows investigators to manage VPS servers and deploy evidence collection projects without touching the evidence data directly.

## Features
1. **Add VPS Servers** - Enter VPS details (IP, SSH user, password) with automatic connectivity testing
2. **Status Monitoring** - Check if VPS servers are active/online
3. **Project Deployment** - Deploy the PHP evidence project to VPS servers via SFTP
4. **Apache Configuration** - Automatically configure virtual hosts on VPS
5. **SSL Certificates** - Set up Let's Encrypt SSL (including wildcard support)
6. **Audit Logging** - Track all operations for compliance

## Project Structure
```
/
├── vps_manager/           # VPS Manager Flask application
│   ├── app.py             # Main Flask application
│   └── templates/         # HTML templates
│       ├── base.html      # Base template with navigation
│       ├── index.html     # Dashboard showing VPS servers
│       ├── add_vps.html   # Add new VPS form
│       ├── view_vps.html  # View VPS details and deployments
│       ├── deploy.html    # Deploy project to VPS
│       └── logs.html      # Audit logs viewer
│
├── admin/                 # PHP Admin Panel (evidence project)
├── page/                  # PHP Page templates
└── config.php             # PHP configuration
```

## User Flow
1. **Add VPS** → User enters VPS details → System checks connectivity
2. **View Active VPS** → Shows server status and Deploy button
3. **Deploy** → Enter domain + optional wildcard checkbox
4. **Apache Setup** → Installs PHP, Apache, configures virtual host
5. **Activate SSL** → Installs Let's Encrypt certificate
6. **Access Admin** → Link to https://domain/admin for license activation

## Technical Details

### Database
- PostgreSQL with three tables:
  - `vps_servers` - VPS server credentials (encrypted)
  - `deployments` - Deployment records
  - `audit_logs` - Action tracking

### Security
- SSH passwords encrypted with Fernet symmetric encryption
- ENCRYPTION_KEY stored in environment variables
- Safe decryption with error handling

### Dependencies
- Flask, Flask-SQLAlchemy
- Paramiko (SSH/SFTP)
- Cryptography (Fernet encryption)
- psycopg2-binary (PostgreSQL)

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection string
- `ENCRYPTION_KEY` - Fernet key for password encryption
- `SECRET_KEY` - Flask session secret

## Running the Application
The VPS Manager runs on port 5000 and is configured via the workflow system.

## Recent Changes
- December 2024: Initial implementation of VPS Manager
  - Added VPS server management with encrypted credentials
  - Implemented SSH connectivity checking
  - Built deployment system with Apache configuration
  - Added SSL activation via Let's Encrypt
  - Created audit logging system
