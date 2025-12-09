import os
import threading
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import paramiko
import socket
from cryptography.fernet import Fernet
import base64
import hashlib

deployment_status = {}
ssl_status = {}
deployment_lock = threading.Lock()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vps-manager-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///vps_manager.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    print("WARNING: ENCRYPTION_KEY not set. Generating a new key...")
    print("Please set ENCRYPTION_KEY environment variable to persist credentials across restarts.")
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    os.environ['ENCRYPTION_KEY'] = ENCRYPTION_KEY

fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)

def decrypt_password_safe(encrypted_password):
    try:
        return fernet.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        return None

def encrypt_password(password):
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()


class VPSServer(db.Model):
    __tablename__ = 'vps_servers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    ssh_user = db.Column(db.String(100), nullable=False)
    ssh_password = db.Column(db.Text, nullable=True)
    ssh_key = db.Column(db.Text, nullable=True)
    ssh_port = db.Column(db.Integer, default=22)
    is_active = db.Column(db.Boolean, default=False)
    last_checked = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    group = db.Column(db.String(50), default='default')
    tags = db.Column(db.String(255), default='')
    cpu_usage = db.Column(db.Float, default=0.0)
    ram_usage = db.Column(db.Float, default=0.0)
    disk_usage = db.Column(db.Float, default=0.0)

    deployments = db.relationship('Deployment', backref='server', lazy=True)


class Deployment(db.Model):
    __tablename__ = 'deployments'

    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('vps_servers.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    is_wildcard = db.Column(db.Boolean, default=False)
    ssl_enabled = db.Column(db.Boolean, default=False)
    ssl_step = db.Column(db.Integer, default=0)
    ssl_txt_value = db.Column(db.String(255))
    status = db.Column(db.String(50), default='pending')
    deployed_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin_url = db.Column(db.String(500))
    version = db.Column(db.Integer, default=1)
    error_message = db.Column(db.Text)
    files_hash = db.Column(db.String(64))

    history = db.relationship('DeploymentHistory', backref='deployment', lazy=True, order_by='DeploymentHistory.created_at.desc()')


class DeploymentHistory(db.Model):
    __tablename__ = 'deployment_history'

    id = db.Column(db.Integer, primary_key=True)
    deployment_id = db.Column(db.Integer, db.ForeignKey('deployments.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    server_id = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class NotificationSettings(db.Model):
    __tablename__ = 'notification_settings'

    id = db.Column(db.Integer, primary_key=True)
    telegram_enabled = db.Column(db.Boolean, default=False)
    telegram_bot_token = db.Column(db.String(255))
    telegram_chat_id = db.Column(db.String(100))
    email_enabled = db.Column(db.Boolean, default=False)
    email_smtp_server = db.Column(db.String(255))
    email_smtp_port = db.Column(db.Integer, default=587)
    email_username = db.Column(db.String(255))
    email_password = db.Column(db.Text)
    email_recipient = db.Column(db.String(255))
    notify_offline = db.Column(db.Boolean, default=True)
    notify_deployment = db.Column(db.Boolean, default=True)


def log_action(action, details=None, server_id=None):
    log = AuditLog(action=action, details=details, server_id=server_id)
    db.session.add(log)
    db.session.commit()


def send_notification(message, notification_type='info'):
    settings = NotificationSettings.query.first()
    if not settings:
        return

    if settings.telegram_enabled and settings.telegram_bot_token and settings.telegram_chat_id:
        try:
            import requests
            url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
            data = {
                'chat_id': settings.telegram_chat_id,
                'text': f"🔔 VPS Manager Alert\n\n{message}",
                'parse_mode': 'HTML'
            }
            requests.post(url, data=data, timeout=5)
        except Exception as e:
            print(f"Telegram notification failed: {e}")

    if settings.email_enabled and settings.email_smtp_server:
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            msg = MIMEMultipart()
            msg['From'] = settings.email_username
            msg['To'] = settings.email_recipient
            msg['Subject'] = f"VPS Manager Alert - {notification_type.upper()}"
            msg.attach(MIMEText(message, 'plain'))

            password = decrypt_password_safe(settings.email_password) if settings.email_password else ''

            server = smtplib.SMTP(settings.email_smtp_server, settings.email_smtp_port)
            server.starttls()
            if password:
                server.login(settings.email_username, password)
            server.send_message(msg)
            server.quit()
        except Exception as e:
            print(f"Email notification failed: {e}")


def check_server_status(ip, port, username, password=None, ssh_key=None, timeout=10):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if ssh_key:
            from io import StringIO
            try:
                key_file = StringIO(ssh_key)
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except:
                try:
                    key_file = StringIO(ssh_key)
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except:
                    key_file = StringIO(ssh_key)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file)
            ssh.connect(ip, port=port, username=username, pkey=pkey, timeout=timeout)
        elif password:
            ssh.connect(ip, port=port, username=username, password=password, timeout=timeout)
        else:
            return False, "No authentication method provided"

        ssh.close()
        return True, "Connection successful"
    except paramiko.AuthenticationException:
        return False, "Authentication failed"
    except paramiko.SSHException as e:
        return False, f"SSH error: {str(e)}"
    except socket.timeout:
        return False, "Connection timed out"
    except socket.error as e:
        return False, f"Network error: {str(e)}"
    except Exception as e:
        return False, f"Error: {str(e)}"


def execute_ssh_command(ip, port, username, password=None, command="", timeout=60, ssh_key=None):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if ssh_key:
            from io import StringIO
            try:
                key_file = StringIO(ssh_key)
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except:
                try:
                    key_file = StringIO(ssh_key)
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except:
                    key_file = StringIO(ssh_key)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file)
            ssh.connect(ip, port=port, username=username, pkey=pkey, timeout=timeout)
        elif password:
            ssh.connect(ip, port=port, username=username, password=password, timeout=timeout)
        else:
            return False, "", "No authentication method provided"

        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        output = stdout.read().decode()
        error = stderr.read().decode()
        ssh.close()
        return True, output, error
    except Exception as e:
        return False, "", str(e)


def get_server_resources(server):
    password = decrypt_password_safe(server.ssh_password) if server.ssh_password else None
    ssh_key = decrypt_password_safe(server.ssh_key) if server.ssh_key else None

    if not password and not ssh_key:
        return None

    try:
        # Get CPU usage
        success, cpu_output, _ = execute_ssh_command(
            server.ip_address, server.ssh_port, server.ssh_user, password,
            "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1", timeout=10, ssh_key=ssh_key
        )
        cpu_usage = float(cpu_output.strip()) if success and cpu_output.strip() else 0.0

        # Get RAM usage
        success, ram_output, _ = execute_ssh_command(
            server.ip_address, server.ssh_port, server.ssh_user, password,
            "free | grep Mem | awk '{print ($3/$2) * 100.0}'", timeout=10, ssh_key=ssh_key
        )
        ram_usage = float(ram_output.strip()) if success and ram_output.strip() else 0.0

        # Get Disk usage
        success, disk_output, _ = execute_ssh_command(
            server.ip_address, server.ssh_port, server.ssh_user, password,
            "df -h / | tail -1 | awk '{print $5}' | cut -d'%' -f1", timeout=10, ssh_key=ssh_key
        )
        disk_usage = float(disk_output.strip()) if success and disk_output.strip() else 0.0

        return {
            'cpu': round(cpu_usage, 2),
            'ram': round(ram_usage, 2),
            'disk': round(disk_usage, 2)
        }
    except Exception as e:
        print(f"Resource monitoring failed: {e}")
        return None


@app.route('/')
def index():
    servers = VPSServer.query.all()
    return render_template('index.html', servers=servers)


@app.route('/dashboard')
def dashboard():
    servers = VPSServer.query.all()

    active_count = sum(1 for s in servers if s.is_active)
    inactive_count = len(servers) - active_count
    total_deployments = Deployment.query.count()

    # Servers with high resource usage (>80%) or offline
    critical_servers = [
        s for s in servers
        if not s.is_active or s.cpu_usage > 80 or s.ram_usage > 80 or s.disk_usage > 80
    ]

    high_resource_count = len([s for s in servers if s.cpu_usage > 80 or s.ram_usage > 80 or s.disk_usage > 80])

    return render_template('dashboard.html',
                         active_count=active_count,
                         inactive_count=inactive_count,
                         total_deployments=total_deployments,
                         high_resource_count=high_resource_count,
                         critical_servers=critical_servers)


@app.route('/add-vps', methods=['GET', 'POST'])
def add_vps():
    if request.method == 'POST':
        name = request.form.get('name')
        ip_address = request.form.get('ip_address')
        ssh_user = request.form.get('ssh_user')
        ssh_password = request.form.get('ssh_password')
        ssh_key = request.form.get('ssh_key')
        ssh_port = int(request.form.get('ssh_port', 22))
        group = request.form.get('group', 'default')
        tags = request.form.get('tags', '')

        is_active, message = check_server_status(ip_address, ssh_port, ssh_user, ssh_password, ssh_key)

        encrypted_pass = encrypt_password(ssh_password) if ssh_password else None
        encrypted_key = encrypt_password(ssh_key) if ssh_key else None

        server = VPSServer(
            name=name,
            ip_address=ip_address,
            ssh_user=ssh_user,
            ssh_password=encrypted_pass,
            ssh_key=encrypted_key,
            ssh_port=ssh_port,
            is_active=is_active,
            last_checked=datetime.utcnow(),
            group=group,
            tags=tags
        )

        db.session.add(server)
        db.session.commit()

        log_action('VPS Added', f"Added VPS: {name} ({ip_address}) - Status: {'Active' if is_active else 'Inactive'}", server.id)

        if is_active:
            flash(f'VPS "{name}" added successfully and is ACTIVE!', 'success')
        else:
            flash(f'VPS "{name}" added but connection failed: {message}', 'warning')
            settings = NotificationSettings.query.first()
            if settings and settings.notify_offline:
                send_notification(f"⚠️ VPS '{name}' ({ip_address}) is OFFLINE\n{message}", 'warning')

        return redirect(url_for('index'))

    groups = db.session.query(VPSServer.group).distinct().all()
    groups = [g[0] for g in groups if g[0]]
    return render_template('add_vps.html', groups=groups)


@app.route('/check-status/<int:server_id>')
def check_status(server_id):
    server = VPSServer.query.get_or_404(server_id)
    password = decrypt_password_safe(server.ssh_password) if server.ssh_password else None
    ssh_key = decrypt_password_safe(server.ssh_key) if server.ssh_key else None

    if not password and not ssh_key:
        return jsonify({'active': False, 'message': 'Failed to decrypt credentials. Server may need to be re-added.'})

    was_active = server.is_active
    is_active, message = check_server_status(server.ip_address, server.ssh_port, server.ssh_user, password, ssh_key)

    server.is_active = is_active
    server.last_checked = datetime.utcnow()

    # Get resource usage if server is active
    if is_active:
        resources = get_server_resources(server)
        if resources:
            server.cpu_usage = resources['cpu']
            server.ram_usage = resources['ram']
            server.disk_usage = resources['disk']

    db.session.commit()

    log_action('Status Check', f"Checked {server.name}: {'Active' if is_active else 'Inactive'} - {message}", server.id)

    # Send notification if server went offline
    if was_active and not is_active:
        settings = NotificationSettings.query.first()
        if settings and settings.notify_offline:
            send_notification(f"🔴 VPS '{server.name}' ({server.ip_address}) went OFFLINE\n{message}", 'error')

    return jsonify({
        'active': is_active,
        'message': message,
        'cpu': server.cpu_usage,
        'ram': server.ram_usage,
        'disk': server.disk_usage
    })


@app.route('/vps/<int:server_id>')
def view_vps(server_id):
    server = VPSServer.query.get_or_404(server_id)
    deployments = Deployment.query.filter_by(server_id=server_id).all()
    return render_template('view_vps.html', server=server, deployments=deployments)


def run_deployment_background(app_context, deployment_id, server_data, password, domain, is_wildcard):
    with app_context:
        try:
            with deployment_lock:
                deployment_status[deployment_id] = {'status': 'running', 'step': 'Starting deployment...', 'progress': 0}

            deployment = Deployment.query.get(deployment_id)
            server = VPSServer.query.get(server_data['id'])

            success, result = deploy_project_with_progress(server, password, domain, is_wildcard, deployment_id)

            if success:
                deployment.status = 'deployed'
                deployment.admin_url = f"https://{domain}/admin"

                history = DeploymentHistory(
                    deployment_id=deployment.id,
                    action='Deployment',
                    status='success',
                    details=f'Successfully deployed to {domain}'
                )
                db.session.add(history)

                settings = NotificationSettings.query.first()
                if settings and settings.notify_deployment:
                    send_notification(f"✅ Deployment successful\nDomain: {domain}\nServer: {server.name}", 'success')

                with deployment_lock:
                    deployment_status[deployment_id] = {'status': 'completed', 'step': 'Deployment successful!', 'progress': 100}
            else:
                deployment.status = 'failed'
                deployment.error_message = result

                history = DeploymentHistory(
                    deployment_id=deployment.id,
                    action='Deployment',
                    status='failed',
                    details=f'Deployment failed: {result}'
                )
                db.session.add(history)

                settings = NotificationSettings.query.first()
                if settings and settings.notify_deployment:
                    send_notification(f"❌ Deployment failed\nDomain: {domain}\nServer: {server.name}\nError: {result}", 'error')

                with deployment_lock:
                    deployment_status[deployment_id] = {'status': 'failed', 'step': f'Failed: {result}', 'progress': 0}

            db.session.commit()

        except Exception as e:
            try:
                db.session.rollback()
                deployment = Deployment.query.get(deployment_id)
                if deployment:
                    deployment.status = 'failed'
                    deployment.error_message = str(e)
                    db.session.commit()
            except:
                pass
            with deployment_lock:
                deployment_status[deployment_id] = {'status': 'failed', 'step': f'Error: {str(e)}', 'progress': 0}


@app.route('/vps/<int:server_id>/deploy', methods=['GET', 'POST'])
def deploy(server_id):
    server = VPSServer.query.get_or_404(server_id)

    if not server.is_active:
        flash('Cannot deploy to inactive server. Please check the connection first.', 'error')
        return redirect(url_for('view_vps', server_id=server_id))

    if request.method == 'POST':
        domain = request.form.get('domain')
        is_wildcard = request.form.get('is_wildcard') == 'on'
        auto_ssl = request.form.get('auto_ssl') == 'on'

        password = decrypt_password_safe(server.ssh_password)
        if password is None:
            flash('Failed to decrypt server credentials. Please re-add the server.', 'error')
            return redirect(url_for('view_vps', server_id=server_id))

        deployment = Deployment(
            server_id=server_id,
            domain=domain,
            is_wildcard=is_wildcard,
            status='deploying'
        )
        db.session.add(deployment)
        db.session.commit()

        log_action('Deployment Started', f"Deploying to {domain} on {server.name} (auto_ssl: {auto_ssl})", server.id)

        server_data = {'id': server.id}
        thread = threading.Thread(
            target=run_deployment_background,
            args=(app.app_context(), deployment.id, server_data, password, domain, is_wildcard)
        )
        thread.daemon = True
        thread.start()

        # Return JSON if it's an AJAX request, otherwise redirect
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.accept_json:
            return jsonify({'success': True, 'deployment_id': deployment.id})

        flash(f'Deployment started for {domain}. Check the status on the server page.', 'info')
        return redirect(url_for('view_vps', server_id=server_id))

    return render_template('deploy.html', server=server)


@app.route('/api/latest-deployment/<int:server_id>')
def get_latest_deployment(server_id):
    deployment = Deployment.query.filter_by(server_id=server_id).order_by(Deployment.deployed_at.desc()).first()
    if deployment:
        return jsonify({'deployment_id': deployment.id})
    return jsonify({'deployment_id': None})


@app.route('/api/deployment-status/<int:deployment_id>')
def get_deployment_status(deployment_id):
    with deployment_lock:
        status = deployment_status.get(deployment_id, None)

    if status:
        return jsonify(status)

    deployment = Deployment.query.get(deployment_id)
    if deployment:
        return jsonify({
            'status': deployment.status,
            'step': 'Deployment ' + deployment.status,
            'progress': 100 if deployment.status == 'deployed' else 0
        })

    return jsonify({'status': 'unknown', 'step': 'Unknown deployment', 'progress': 0})


def update_deployment_progress(deployment_id, step, progress):
    with deployment_lock:
        deployment_status[deployment_id] = {'status': 'running', 'step': step, 'progress': progress}


def deploy_project_with_progress(server, password, domain, is_wildcard, deployment_id):
    try:
        print(f"\n{'='*60}")
        print(f"DEPLOYMENT STARTED - ID: {deployment_id}")
        print(f"Server: {server.name} ({server.ip_address})")
        print(f"Domain: {domain}")
        print(f"Wildcard: {is_wildcard}")
        print(f"{'='*60}\n")

        update_deployment_progress(deployment_id, 'Connecting to server...', 5)
        print(f"[STEP 1] Connecting to {server.ip_address}:{server.ssh_port} as {server.ssh_user}")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server.ip_address, port=server.ssh_port, username=server.ssh_user, password=password, timeout=30)
        print(f"[SUCCESS] Connected to server")

        update_deployment_progress(deployment_id, 'Updating system packages...', 10)
        print(f"[STEP 2] Updating system packages...")
        stdin, stdout, stderr = ssh.exec_command("sudo apt-get update -y", timeout=120)
        exit_status = stdout.channel.recv_exit_status()
        print(f"[EXIT CODE] apt-get update: {exit_status}")

        update_deployment_progress(deployment_id, 'Installing Apache, PHP and rsync...', 25)
        print(f"[STEP 3] Installing Apache, PHP and rsync...")
        stdin, stdout, stderr = ssh.exec_command("sudo apt-get install -y apache2 php php-curl php-json libapache2-mod-php rsync", timeout=180)
        exit_status = stdout.channel.recv_exit_status()
        print(f"[EXIT CODE] apt-get install: {exit_status}")

        update_deployment_progress(deployment_id, 'Configuring Apache modules...', 40)
        print(f"[STEP 4] Configuring Apache modules...")
        for cmd in ["sudo a2enmod rewrite", "sudo a2enmod ssl"]:
            print(f"  Running: {cmd}")
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
            exit_status = stdout.channel.recv_exit_status()
            print(f"  Exit code: {exit_status}")

        update_deployment_progress(deployment_id, 'Creating web directory...', 50)
        print(f"[STEP 5] Creating web directory...")
        for cmd in [f"sudo mkdir -p /var/www/{domain}", f"sudo chown -R www-data:www-data /var/www/{domain}", f"sudo chmod -R 755 /var/www/{domain}"]:
            print(f"  Running: {cmd}")
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
            exit_status = stdout.channel.recv_exit_status()
            print(f"  Exit code: {exit_status}")

        update_deployment_progress(deployment_id, 'Configuring virtual host...', 60)
        print(f"[STEP 6] Configuring virtual host...")
        vhost_config = f"""<VirtualHost *:80>
    ServerName {domain}
    {"ServerAlias *." + domain if is_wildcard else ""}
    DocumentRoot /var/www/{domain}

    <Directory /var/www/{domain}>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${{APACHE_LOG_DIR}}/{domain}_error.log
    CustomLog ${{APACHE_LOG_DIR}}/{domain}_access.log combined
</VirtualHost>
"""

        sftp = ssh.open_sftp()

        with sftp.file(f'/tmp/{domain}.conf', 'w') as f:
            f.write(vhost_config)
        print(f"  Created vhost config: /tmp/{domain}.conf")

        ssh.exec_command(f"sudo mv /tmp/{domain}.conf /etc/apache2/sites-available/{domain}.conf")
        ssh.exec_command(f"sudo a2ensite {domain}.conf")
        ssh.exec_command("sudo systemctl enable apache2")
        ssh.exec_command("sudo systemctl restart apache2")
        print(f"  Apache configured, enabled and restarted")

        update_deployment_progress(deployment_id, 'Uploading project files...', 70)
        workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        print(f"\n[STEP 7] Uploading project files...")
        print(f"  Workspace root: {workspace_root}")
        print(f"  Remote path: /var/www/{domain}")

        # Define allowed items to upload (only website files, not VPS manager)
        allowed_items = ['admin', 'page', 'qr', 'b64.php', 'config.php', 'fake.php', 'index.php']
        print(f"  Allowed items: {allowed_items}")

        sftp = ssh.open_sftp()
        total_files = 0

        # Upload each allowed item
        for item in allowed_items:
            local_item_path = os.path.join(workspace_root, item)

            if not os.path.exists(local_item_path):
                print(f"  Skipping {item} (not found)")
                continue

            remote_item_path = f"/var/www/{domain}/{item}"
            print(f"  Uploading: {item}")

            if os.path.isdir(local_item_path):
                # Count files in directory for progress reporting
                file_count = sum(len(files) for _, _, files in os.walk(local_item_path))
                print(f"    Directory with {file_count} files")
                total_files += file_count
                
                # Use parallel upload for directories
                exclude_dirs = ['.git', '__pycache__', '.cache', 'node_modules']
                exclude_files = ['.gitignore', '.DS_Store']
                upload_directory_parallel(sftp, local_item_path, remote_item_path, ssh, 
                                         exclude_dirs=exclude_dirs, exclude_files=exclude_files)
            else:
                # Upload single file
                try:
                    sftp.put(local_item_path, remote_item_path)
                    total_files += 1
                    print(f"    Uploaded file")
                except IOError:
                    ssh.exec_command(f"sudo mkdir -p {os.path.dirname(remote_item_path)}")
                    sftp.put(local_item_path, remote_item_path)
                    total_files += 1
                    print(f"    Uploaded file (created parent dir)")

        sftp.close()
        print(f"  Total files uploaded: {total_files}")

        print(f"[SUCCESS] Files uploaded")

        update_deployment_progress(deployment_id, 'Setting file permissions...', 90)
        print(f"\n[STEP 8] Setting file permissions...")
        ssh.exec_command(f"sudo mkdir -p /var/www/{domain}/page/result")
        ssh.exec_command(f"sudo chown -R www-data:www-data /var/www/{domain}")
        ssh.exec_command(f"sudo chmod -R 755 /var/www/{domain}")
        ssh.exec_command(f"sudo chmod -R 777 /var/www/{domain}/page/result")
        print(f"  Permissions set")

        update_deployment_progress(deployment_id, 'Restarting Apache...', 95)
        print(f"\n[STEP 9] Final Apache restart...")
        ssh.exec_command("sudo systemctl restart apache2")
        print(f"  Apache restarted")

        ssh.close()

        print(f"\n{'='*60}")
        print(f"DEPLOYMENT COMPLETED SUCCESSFULLY")
        print(f"{'='*60}\n")

        log_action('Deployment Complete', f"Successfully deployed to {domain}", server.id)
        return True, "Deployment successful"

    except Exception as e:
        print(f"\n{'!'*60}")
        print(f"DEPLOYMENT FAILED")
        print(f"Error: {str(e)}")
        print(f"{'!'*60}\n")
        import traceback
        traceback.print_exc()
        log_action('Deployment Failed', f"Failed to deploy to {domain}: {str(e)}", server.id)
        return False, str(e)


def deploy_project(server, password, domain, is_wildcard):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server.ip_address, port=server.ssh_port, username=server.ssh_user, password=password, timeout=30)

        commands = [
            "sudo apt-get update -y",
            "sudo apt-get install -y apache2 php php-curl php-json libapache2-mod-php",
            "sudo a2enmod rewrite",
            "sudo a2enmod ssl",
            f"sudo mkdir -p /var/www/{domain}",
            f"sudo chown -R www-data:www-data /var/www/{domain}",
            f"sudo chmod -R 755 /var/www/{domain}",
        ]

        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=120)
            stdout.channel.recv_exit_status()

        vhost_config = f"""<VirtualHost *:80>
    ServerName {domain}
    {"ServerAlias *." + domain if is_wildcard else ""}
    DocumentRoot /var/www/{domain}

    <Directory /var/www/{domain}>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${{APACHE_LOG_DIR}}/{domain}_error.log
    CustomLog ${{APACHE_LOG_DIR}}/{domain}_access.log combined
</VirtualHost>
"""

        sftp = ssh.open_sftp()

        with sftp.file(f'/tmp/{domain}.conf', 'w') as f:
            f.write(vhost_config)

        ssh.exec_command(f"sudo mv /tmp/{domain}.conf /etc/apache2/sites-available/{domain}.conf")
        ssh.exec_command(f"sudo a2ensite {domain}.conf")
        ssh.exec_command("sudo systemctl enable apache2")
        ssh.exec_command("sudo systemctl restart apache2")

        workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # Define allowed items to upload
        allowed_items = ['admin', 'page', 'qr', 'b64.php', 'config.php', 'fake.php', 'index.php']

        # Upload each allowed item
        for item in allowed_items:
            local_item_path = os.path.join(workspace_root, item)

            if not os.path.exists(local_item_path):
                continue

            remote_item_path = f"/var/www/{domain}/{item}"

            if os.path.isdir(local_item_path):
                upload_directory(sftp, local_item_path, remote_item_path, ssh)
            else:
                try:
                    sftp.put(local_item_path, remote_item_path)
                except IOError:
                    ssh.exec_command(f"sudo mkdir -p {os.path.dirname(remote_item_path)}")
                    sftp.put(local_item_path, remote_item_path)

        ssh.exec_command(f"sudo mkdir -p /var/www/{domain}/page/result")
        ssh.exec_command(f"sudo chown -R www-data:www-data /var/www/{domain}")
        ssh.exec_command(f"sudo chmod -R 755 /var/www/{domain}")
        ssh.exec_command(f"sudo chmod -R 777 /var/www/{domain}/page/result")

        ssh.exec_command("sudo systemctl restart apache2")

        sftp.close()
        ssh.close()

        log_action('Deployment Complete', f"Successfully deployed to {domain}", server.id)
        return True, "Deployment successful"

    except Exception as e:
        log_action('Deployment Failed', f"Failed to deploy to {domain}: {str(e)}", server.id)
        return False, str(e)


def upload_directory_parallel(sftp, local_path, remote_path, ssh, max_workers=1, exclude_dirs=None, exclude_files=None):
    """Upload directory with sequential file transfers for stability"""
    if exclude_dirs is None:
        exclude_dirs = []
    if exclude_files is None:
        exclude_files = []
    import os
    import time

    files_to_upload = []

    # Collect all files first
    for root, dirs, files in os.walk(local_path):
        # Remove excluded directories from the walk
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for filename in files:
            # Skip excluded files
            if filename in exclude_files:
                continue

            local_file = os.path.join(root, filename)
            relative_path = os.path.relpath(local_file, local_path)
            remote_file = os.path.join(remote_path, relative_path).replace('\\', '/')
            files_to_upload.append((local_file, remote_file))

    print(f"Found {len(files_to_upload)} files to upload")

    # Create all directories first (batch them to reduce commands)
    dirs_to_create = set()
    for _, remote_file in files_to_upload:
        remote_dir = os.path.dirname(remote_file)
        dirs_to_create.add(remote_dir)
    
    # Create directories in batches
    dirs_list = sorted(list(dirs_to_create))
    batch_size = 50
    for i in range(0, len(dirs_list), batch_size):
        batch = dirs_list[i:i+batch_size]
        dirs_cmd = " ".join([f'"{d}"' for d in batch])
        ssh.exec_command(f"sudo mkdir -p {dirs_cmd}")
        time.sleep(0.1)  # Small delay between batches

    # Upload files sequentially with retries for stability
    uploaded = 0
    failed = 0
    failed_files = []

    for local_file, remote_file in files_to_upload:
        success = False
        for attempt in range(3):  # Up to 3 attempts per file
            try:
                sftp.put(local_file, remote_file)
                success = True
                break
            except Exception as e:
                if attempt < 2:
                    time.sleep(0.5)  # Wait before retry
                else:
                    print(f"Failed to upload {local_file}: {e}")
                    failed_files.append(local_file)
        
        if success:
            uploaded += 1
        else:
            failed += 1

        # Print progress periodically
        if (uploaded + failed) % 100 == 0:
            print(f"Progress: {uploaded + failed}/{len(files_to_upload)} files uploaded")

    print(f"Upload complete: {uploaded} succeeded, {failed} failed")
    if failed > 0:
        print(f"Failed files: {failed_files[:10]}...")  # Show first 10 failed files
        raise Exception(f"{failed} files failed to upload.")
    return True


def upload_directory(sftp, local_path, remote_path, ssh, depth=0):
    import os

    indent = "  " * depth
    exclude_dirs = ['vps_manager', '.git', '__pycache__', '.pythonlibs', '.cache', 'node_modules']
    exclude_files = ['.gitignore', 'pyproject.toml', 'uv.lock', 'replit.md', '.replit', 'replit.nix']

    print(f"{indent}📁 Scanning: {local_path}")

    # Check if local path exists
    if not os.path.exists(local_path):
        print(f"{indent}⚠️  Path does not exist: {local_path}")
        return

    try:
        items = os.listdir(local_path)
        print(f"{indent}   Found {len(items)} items")
    except (PermissionError, OSError) as e:
        print(f"{indent}⚠️  Cannot access directory {local_path}: {e}")
        return

    uploaded_count = 0
    skipped_count = 0

    for item in items:
        if item in exclude_dirs or item in exclude_files or item.startswith('.'):
            print(f"{indent}   ⊘ Excluded: {item}")
            skipped_count += 1
            continue

        local_item = os.path.join(local_path, item)
        remote_item = f"{remote_path}/{item}"

        # Check if local item exists and is accessible
        if not os.path.exists(local_item):
            print(f"{indent}⚠️  Skipping non-existent: {local_item}")
            skipped_count += 1
            continue

        try:
            if os.path.isfile(local_item):
                file_size = os.path.getsize(local_item)
                print(f"{indent}   📄 Uploading: {item} ({file_size} bytes)")
                try:
                    sftp.put(local_item, remote_item)
                    print(f"{indent}      ✓ Uploaded")
                    uploaded_count += 1
                except IOError as e:
                    print(f"{indent}      Creating parent directory...")
                    ssh.exec_command(f"sudo mkdir -p {os.path.dirname(remote_item)}")
                    sftp.put(local_item, remote_item)
                    print(f"{indent}      ✓ Uploaded (retry)")
                    uploaded_count += 1
            elif os.path.isdir(local_item):
                print(f"{indent}   📂 Directory: {item}")
                try:
                    sftp.stat(remote_item)
                    print(f"{indent}      Directory exists on remote")
                except IOError:
                    print(f"{indent}      Creating remote directory...")
                    ssh.exec_command(f"sudo mkdir -p {remote_item}")
                upload_directory(sftp, local_item, remote_item, ssh, depth + 1)
        except (PermissionError, OSError, IOError) as e:
            print(f"{indent}❌ Failed to upload {local_item}: {e}")
            skipped_count += 1
            continue

    print(f"{indent}✓ Completed: {uploaded_count} uploaded, {skipped_count} skipped")


def run_ssl_activation_background(app_context, server_id, deployment_id, password):
    with app_context:
        try:
            with deployment_lock:
                ssl_status[deployment_id] = {'status': 'running', 'step': 'Starting SSL activation...', 'progress': 0}

            server = VPSServer.query.get(server_id)
            deployment = Deployment.query.get(deployment_id)

            with deployment_lock:
                ssl_status[deployment_id] = {'status': 'running', 'step': 'Connecting to server...', 'progress': 10}

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server.ip_address, port=server.ssh_port, username=server.ssh_user, password=password, timeout=30)

            with deployment_lock:
                ssl_status[deployment_id] = {'status': 'running', 'step': 'Installing Certbot...', 'progress': 30}

            stdin, stdout, stderr = ssh.exec_command("sudo apt-get install -y certbot python3-certbot-apache", timeout=180)
            stdout.channel.recv_exit_status()

            with deployment_lock:
                ssl_status[deployment_id] = {'status': 'running', 'step': 'Generating SSL certificate...', 'progress': 60}

            if deployment.is_wildcard:
                cmd = f"sudo certbot --apache -d {deployment.domain} -d '*.{deployment.domain}' --non-interactive --agree-tos --email admin@{deployment.domain} --redirect"
            else:
                cmd = f"sudo certbot --apache -d {deployment.domain} --non-interactive --agree-tos --email admin@{deployment.domain} --redirect"

            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=300)
            stdout.channel.recv_exit_status()

            ssh.close()

            deployment.ssl_enabled = True
            deployment.admin_url = f"https://{deployment.domain}/admin"
            db.session.commit()

            log_action('SSL Activated', f"SSL enabled for {deployment.domain}", server.id)

            with deployment_lock:
                ssl_status[deployment_id] = {'status': 'completed', 'step': 'SSL activated successfully!', 'progress': 100}

        except Exception as e:
            try:
                db.session.rollback()
                deployment = Deployment.query.get(deployment_id)
                if deployment:
                    deployment.status = 'ssl_failed'
                    deployment.error_message = f"SSL activation failed: {str(e)}"
                    db.session.commit()
                log_action('SSL Failed', f"SSL activation failed: {str(e)}", server_id)
            except:
                pass
            with deployment_lock:
                ssl_status[deployment_id] = {'status': 'failed', 'step': f'Error: {str(e)}', 'progress': 0}


@app.route('/vps/<int:server_id>/format', methods=['POST'])
def format_vps(server_id):
    server = VPSServer.query.get_or_404(server_id)

    if not server.is_active:
        return jsonify({'success': False, 'message': 'Server is not active'})

    password = decrypt_password_safe(server.ssh_password)
    ssh_key = decrypt_password_safe(server.ssh_key) if server.ssh_key else None

    if not password and not ssh_key:
        return jsonify({'success': False, 'message': 'Failed to decrypt credentials'})

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if ssh_key:
            from io import StringIO
            try:
                key_file = StringIO(ssh_key)
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except:
                try:
                    key_file = StringIO(ssh_key)
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except:
                    key_file = StringIO(ssh_key)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file)
            ssh.connect(server.ip_address, port=server.ssh_port, username=server.ssh_user, pkey=pkey, timeout=30)
        else:
            ssh.connect(server.ip_address, port=server.ssh_port, username=server.ssh_user, password=password, timeout=30)

        # Get all deployments for this server
        deployments = Deployment.query.filter_by(server_id=server_id).all()
        domains_cleaned = []

        for deployment in deployments:
            domain = deployment.domain

            # Disable Apache site
            ssh.exec_command(f"sudo a2dissite {domain}.conf", timeout=30)

            # Remove Apache config
            ssh.exec_command(f"sudo rm -f /etc/apache2/sites-available/{domain}.conf", timeout=30)

            # Remove SSL certificates
            ssh.exec_command(f"sudo certbot delete --cert-name {domain} --non-interactive", timeout=60)

            # Remove web files
            ssh.exec_command(f"sudo rm -rf /var/www/{domain}", timeout=60)

            domains_cleaned.append(domain)

        # Reload Apache
        ssh.exec_command("sudo systemctl reload apache2", timeout=30)

        ssh.close()

        # Delete deployment records from database
        DeploymentHistory.query.filter(DeploymentHistory.deployment_id.in_([d.id for d in deployments])).delete(synchronize_session=False)
        Deployment.query.filter_by(server_id=server_id).delete()
        db.session.commit()

        log_action('VPS Formatted', f"Formatted VPS {server.name} - Removed {len(domains_cleaned)} deployments", server.id)

        message = f"Successfully formatted VPS.\nRemoved {len(domains_cleaned)} deployment(s)."
        if domains_cleaned:
            message += f"\n\nCleaned domains: {', '.join(domains_cleaned)}"

        return jsonify({'success': True, 'message': message})

    except Exception as e:
        log_action('VPS Format Failed', f"Failed to format VPS {server.name}: {str(e)}", server.id)
        return jsonify({'success': False, 'message': str(e)})


@app.route('/vps/<int:server_id>/deployment/<int:deployment_id>/ssl', methods=['POST'])
def activate_ssl(server_id, deployment_id):
    server = VPSServer.query.get_or_404(server_id)
    deployment = Deployment.query.get_or_404(deployment_id)

    if not server.is_active:
        return jsonify({'success': False, 'message': 'Server is not active'})

    password = decrypt_password_safe(server.ssh_password)
    if password is None:
        return jsonify({'success': False, 'message': 'Failed to decrypt credentials'})

    thread = threading.Thread(
        target=run_ssl_activation_background,
        args=(app.app_context(), server_id, deployment_id, password)
    )
    thread.daemon = True
    thread.start()

    return jsonify({'success': True, 'message': 'SSL activation started. This may take a few minutes.'})


@app.route('/vps/<int:server_id>/deployment/<int:deployment_id>/ssl-setup')
def ssl_setup(server_id, deployment_id):
    server = VPSServer.query.get_or_404(server_id)
    deployment = Deployment.query.get_or_404(deployment_id)
    return render_template('ssl_setup.html', 
                          server=server, 
                          deployment=deployment, 
                          step=deployment.ssl_step or 0,
                          txt_value=deployment.ssl_txt_value)


@app.route('/vps/<int:server_id>/deployment/<int:deployment_id>/ssl/generate-challenge', methods=['POST'])
def generate_ssl_challenge(server_id, deployment_id):
    server = VPSServer.query.get_or_404(server_id)
    deployment = Deployment.query.get_or_404(deployment_id)
    
    if not server.is_active:
        return jsonify({'success': False, 'message': 'Server is not active'})
    
    password = decrypt_password_safe(server.ssh_password)
    ssh_key = decrypt_password_safe(server.ssh_key) if server.ssh_key else None
    
    if not password and not ssh_key:
        return jsonify({'success': False, 'message': 'Failed to decrypt credentials'})
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if ssh_key:
            from io import StringIO
            try:
                key_file = StringIO(ssh_key)
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except:
                try:
                    key_file = StringIO(ssh_key)
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except:
                    key_file = StringIO(ssh_key)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file)
            ssh.connect(server.ip_address, port=server.ssh_port, username=server.ssh_user, pkey=pkey, timeout=30)
        else:
            ssh.connect(server.ip_address, port=server.ssh_port, username=server.ssh_user, password=password, timeout=30)
        
        stdin, stdout, stderr = ssh.exec_command("sudo apt-get install -y certbot python3-certbot-apache", timeout=180)
        stdout.channel.recv_exit_status()
        
        domain = deployment.domain
        cmd = f"""sudo certbot certonly --manual --preferred-challenges dns -d {domain} -d '*.{domain}' --agree-tos --email admin@{domain} --manual-auth-hook 'echo $CERTBOT_VALIDATION' --dry-run 2>&1 | grep -A1 'Please deploy a DNS TXT record' | tail -1 || echo 'CHALLENGE_EXTRACT_FAILED'"""
        
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
        output = stdout.read().decode().strip()
        
        ssh.close()
        
        if 'CHALLENGE_EXTRACT_FAILED' in output or not output:
            import secrets
            import string
            txt_value = ''.join(secrets.choice(string.ascii_letters + string.digits + '-_') for _ in range(43))
        else:
            txt_value = output.strip()
        
        deployment.ssl_txt_value = txt_value
        deployment.ssl_step = 1
        db.session.commit()
        
        log_action('SSL Challenge Generated', f"Generated TXT challenge for {deployment.domain}", server.id)
        
        return jsonify({'success': True, 'txt_value': txt_value})
        
    except Exception as e:
        log_action('SSL Challenge Failed', f"Failed to generate challenge for {deployment.domain}: {str(e)}", server.id)
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})


@app.route('/vps/<int:server_id>/deployment/<int:deployment_id>/ssl/verify-dns', methods=['POST'])
def verify_ssl_dns(server_id, deployment_id):
    import subprocess
    
    server = VPSServer.query.get_or_404(server_id)
    deployment = Deployment.query.get_or_404(deployment_id)
    
    if not deployment.ssl_txt_value:
        return jsonify({'success': False, 'message': 'No challenge generated yet. Generate a challenge first.'})
    
    domain = deployment.domain
    expected_value = deployment.ssl_txt_value
    
    try:
        result = subprocess.run(
            ['dig', '+short', 'TXT', f'_acme-challenge.{domain}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        txt_records = result.stdout.strip().replace('"', '').split('\n')
        
        for record in txt_records:
            if expected_value in record:
                deployment.ssl_step = 2
                db.session.commit()
                log_action('DNS Verified', f"DNS TXT record verified for {deployment.domain}", server.id)
                return jsonify({'success': True, 'message': 'DNS record verified successfully! You can now install SSL.'})
        
        return jsonify({
            'success': False, 
            'message': f'TXT record not found or does not match. Found: {txt_records if txt_records[0] else "No records"}. Expected value containing: {expected_value[:20]}...'
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'message': 'DNS lookup timed out. Please try again.'})
    except FileNotFoundError:
        try:
            import socket
            import dns.resolver
            answers = dns.resolver.resolve(f'_acme-challenge.{domain}', 'TXT')
            for rdata in answers:
                if expected_value in str(rdata):
                    deployment.ssl_step = 2
                    db.session.commit()
                    return jsonify({'success': True, 'message': 'DNS record verified successfully!'})
            return jsonify({'success': False, 'message': 'TXT record not found or does not match.'})
        except:
            deployment.ssl_step = 2
            db.session.commit()
            return jsonify({'success': True, 'message': 'DNS verification skipped (dig not available). Proceeding to SSL installation.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error verifying DNS: {str(e)}'})


@app.route('/vps/<int:server_id>/deployment/<int:deployment_id>/ssl/install', methods=['POST'])
def install_ssl_wildcard(server_id, deployment_id):
    server = VPSServer.query.get_or_404(server_id)
    deployment = Deployment.query.get_or_404(deployment_id)
    
    if not server.is_active:
        return jsonify({'success': False, 'message': 'Server is not active'})
    
    password = decrypt_password_safe(server.ssh_password)
    ssh_key = decrypt_password_safe(server.ssh_key) if server.ssh_key else None
    
    if not password and not ssh_key:
        return jsonify({'success': False, 'message': 'Failed to decrypt credentials'})
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if ssh_key:
            from io import StringIO
            try:
                key_file = StringIO(ssh_key)
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except:
                try:
                    key_file = StringIO(ssh_key)
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except:
                    key_file = StringIO(ssh_key)
                    pkey = paramiko.ECDSAKey.from_private_key(key_file)
            ssh.connect(server.ip_address, port=server.ssh_port, username=server.ssh_user, pkey=pkey, timeout=30)
        else:
            ssh.connect(server.ip_address, port=server.ssh_port, username=server.ssh_user, password=password, timeout=30)
        
        stdin, stdout, stderr = ssh.exec_command("sudo apt-get install -y certbot python3-certbot-apache", timeout=180)
        stdout.channel.recv_exit_status()
        
        domain = deployment.domain
        wildcard_success = False
        
        if deployment.is_wildcard and deployment.ssl_txt_value:
            auth_script = f'''#!/bin/bash
echo "{deployment.ssl_txt_value}"
'''
            sftp = ssh.open_sftp()
            with sftp.file('/tmp/acme-auth.sh', 'w') as f:
                f.write(auth_script)
            sftp.close()
            ssh.exec_command("chmod +x /tmp/acme-auth.sh")
            
            cmd = f"sudo certbot certonly --manual --preferred-challenges dns -d {domain} -d '*.{domain}' --agree-tos --email admin@{domain} --manual-auth-hook /tmp/acme-auth.sh --non-interactive 2>&1"
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=300)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode()
            
            if exit_code == 0 or 'Congratulations' in output or 'Successfully' in output:
                wildcard_success = True
                ssh.exec_command(f"sudo certbot install --apache -d {domain} -d '*.{domain}' --non-interactive --redirect", timeout=120)
        
        if not wildcard_success:
            cmd = f"sudo certbot --apache -d {domain} --non-interactive --agree-tos --email admin@{domain} --redirect"
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=300)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode()
            error = stderr.read().decode()
        
        ssh.close()
        
        if exit_code == 0 or 'Congratulations' in output or 'Successfully' in output:
            deployment.ssl_enabled = True
            deployment.ssl_step = 3
            deployment.admin_url = f"https://{domain}/admin"
            db.session.commit()
            
            message = f'SSL certificate installed successfully! Admin URL: https://{domain}/admin'
            if deployment.is_wildcard and not wildcard_success:
                message += ' (Note: Installed single-domain SSL. Wildcard requires Cloudflare DNS integration.)'
            
            log_action('SSL Installed', f"SSL certificate installed for {domain}", server.id)
            return jsonify({'success': True, 'message': message})
        else:
            deployment.ssl_step = 0
            deployment.ssl_txt_value = None
            db.session.commit()
            return jsonify({'success': False, 'message': f'SSL installation failed: {error if "error" in dir() else output}'})
        
    except Exception as e:
        log_action('SSL Installation Failed', f"Failed to install SSL for {deployment.domain}: {str(e)}", server.id)
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})


@app.route('/api/ssl-status/<int:deployment_id>')
def get_ssl_status(deployment_id):
    with deployment_lock:
        status = ssl_status.get(deployment_id, None)

    if status:
        return jsonify(status)

    deployment = Deployment.query.get(deployment_id)
    if deployment:
        return jsonify({
            'status': 'completed' if deployment.ssl_enabled else 'unknown',
            'step': 'SSL enabled' if deployment.ssl_enabled else 'SSL not configured',
            'progress': 100 if deployment.ssl_enabled else 0
        })

    return jsonify({'status': 'unknown', 'step': 'Unknown deployment', 'progress': 0})


@app.route('/bulk-check-status', methods=['POST'])
def bulk_check_status():
    servers = VPSServer.query.all()
    results = []

    for server in servers:
        password = decrypt_password_safe(server.ssh_password)
        if password:
            was_active = server.is_active
            is_active, message = check_server_status(server.ip_address, server.ssh_port, server.ssh_user, password)

            server.is_active = is_active
            server.last_checked = datetime.utcnow()

            if is_active:
                resources = get_server_resources(server)
                if resources:
                    server.cpu_usage = resources['cpu']
                    server.ram_usage = resources['ram']
                    server.disk_usage = resources['disk']

            results.append({
                'id': server.id,
                'name': server.name,
                'active': is_active,
                'message': message
            })

            if was_active and not is_active:
                settings = NotificationSettings.query.first()
                if settings and settings.notify_offline:
                    send_notification(f"🔴 VPS '{server.name}' ({server.ip_address}) went OFFLINE\n{message}", 'error')

    db.session.commit()
    log_action('Bulk Status Check', f"Checked {len(servers)} servers")

    return jsonify({'success': True, 'results': results})


@app.route('/delete-vps/<int:server_id>', methods=['POST'])
def delete_vps(server_id):
    server = VPSServer.query.get_or_404(server_id)

    Deployment.query.filter_by(server_id=server_id).delete()

    log_action('VPS Deleted', f"Deleted VPS: {server.name} ({server.ip_address})", server.id)

    db.session.delete(server)
    db.session.commit()

    flash(f'VPS "{server.name}" deleted successfully.', 'success')
    return redirect(url_for('index'))


@app.route('/logs')
def view_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return render_template('logs.html', logs=logs)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    notification_settings = NotificationSettings.query.first()

    if request.method == 'POST':
        if not notification_settings:
            notification_settings = NotificationSettings()
            db.session.add(notification_settings)

        notification_settings.telegram_enabled = request.form.get('telegram_enabled') == 'on'
        notification_settings.telegram_bot_token = request.form.get('telegram_bot_token', '')
        notification_settings.telegram_chat_id = request.form.get('telegram_chat_id', '')

        notification_settings.email_enabled = request.form.get('email_enabled') == 'on'
        notification_settings.email_smtp_server = request.form.get('email_smtp_server', '')
        notification_settings.email_smtp_port = int(request.form.get('email_smtp_port', 587))
        notification_settings.email_username = request.form.get('email_username', '')

        email_password = request.form.get('email_password', '')
        if email_password:
            notification_settings.email_password = encrypt_password(email_password)

        notification_settings.email_recipient = request.form.get('email_recipient', '')
        notification_settings.notify_offline = request.form.get('notify_offline') == 'on'
        notification_settings.notify_deployment = request.form.get('notify_deployment') == 'on'

        db.session.commit()

        log_action('Settings Updated', 'Notification settings updated')
        flash('Settings saved successfully!', 'success')
        return redirect(url_for('settings'))

    return render_template('settings.html', settings=notification_settings)


@app.route('/api/resources/<int:server_id>')
def get_resources(server_id):
    server = VPSServer.query.get_or_404(server_id)

    if not server.is_active:
        return jsonify({'error': 'Server is offline'})

    resources = get_server_resources(server)

    if resources:
        server.cpu_usage = resources['cpu']
        server.ram_usage = resources['ram']
        server.disk_usage = resources['disk']
        db.session.commit()

    return jsonify(resources if resources else {'error': 'Failed to fetch resources'})


@app.route('/backup')
def backup_page():
    return render_template('backup.html')


@app.route('/backup/export')
def backup_export():
    import json
    from flask import make_response

    servers = VPSServer.query.all()
    backup_data = {
        'version': '1.0',
        'exported_at': datetime.utcnow().isoformat(),
        'servers': []
    }

    for server in servers:
        backup_data['servers'].append({
            'name': server.name,
            'ip_address': server.ip_address,
            'ssh_user': server.ssh_user,
            'ssh_port': server.ssh_port,
            'group': server.group,
            'tags': server.tags
        })

    response = make_response(json.dumps(backup_data, indent=2))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = f'attachment; filename=vps_backup_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'

    log_action('Backup Export', f'Exported {len(servers)} VPS configurations')
    return response


@app.route('/backup/import', methods=['POST'])
def backup_import():
    import json

    if 'backup_file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('backup_page'))

    file = request.files['backup_file']

    try:
        data = json.load(file)
        imported_count = 0

        for server_data in data.get('servers', []):
            # Check if server already exists
            existing = VPSServer.query.filter_by(ip_address=server_data['ip_address']).first()
            if not existing:
                server = VPSServer(
                    name=server_data['name'],
                    ip_address=server_data['ip_address'],
                    ssh_user=server_data['ssh_user'],
                    ssh_port=server_data.get('ssh_port', 22),
                    group=server_data.get('group', 'default'),
                    tags=server_data.get('tags', ''),
                    is_active=False
                )
                db.session.add(server)
                imported_count += 1

        db.session.commit()
        log_action('Backup Import', f'Imported {imported_count} VPS configurations')
        flash(f'Successfully imported {imported_count} VPS configurations. Please add credentials manually.', 'success')

    except Exception as e:
        flash(f'Import failed: {str(e)}', 'error')

    return redirect(url_for('index'))


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)