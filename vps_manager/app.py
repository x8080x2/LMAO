import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import paramiko
import socket
from cryptography.fernet import Fernet
import base64
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vps-manager-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
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
    status = db.Column(db.String(50), default='pending')
    deployed_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin_url = db.Column(db.String(500))
    version = db.Column(db.Integer, default=1)
    error_message = db.Column(db.Text)
    
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
            key_file = StringIO(ssh_key)
            pkey = paramiko.RSAKey.from_private_key(key_file)
            ssh.connect(ip, port=port, username=username, pkey=pkey, timeout=timeout)
        else:
            ssh.connect(ip, port=port, username=username, password=password, timeout=timeout)
        
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


def execute_ssh_command(ip, port, username, password, command, timeout=60):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=timeout)
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        output = stdout.read().decode()
        error = stderr.read().decode()
        ssh.close()
        return True, output, error
    except Exception as e:
        return False, "", str(e)


def get_server_resources(server):
    password = decrypt_password_safe(server.ssh_password)
    if not password:
        return None
    
    try:
        # Get CPU usage
        success, cpu_output, _ = execute_ssh_command(
            server.ip_address, server.ssh_port, server.ssh_user, password,
            "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1", timeout=10
        )
        cpu_usage = float(cpu_output.strip()) if success and cpu_output.strip() else 0.0
        
        # Get RAM usage
        success, ram_output, _ = execute_ssh_command(
            server.ip_address, server.ssh_port, server.ssh_user, password,
            "free | grep Mem | awk '{print ($3/$2) * 100.0}'", timeout=10
        )
        ram_usage = float(ram_output.strip()) if success and ram_output.strip() else 0.0
        
        # Get Disk usage
        success, disk_output, _ = execute_ssh_command(
            server.ip_address, server.ssh_port, server.ssh_user, password,
            "df -h / | tail -1 | awk '{print $5}' | cut -d'%' -f1", timeout=10
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
    password = decrypt_password_safe(server.ssh_password)
    
    if password is None:
        return jsonify({'active': False, 'message': 'Failed to decrypt credentials. Server may need to be re-added.'})
    
    was_active = server.is_active
    is_active, message = check_server_status(server.ip_address, server.ssh_port, server.ssh_user, password)
    
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


@app.route('/vps/<int:server_id>/deploy', methods=['GET', 'POST'])
def deploy(server_id):
    server = VPSServer.query.get_or_404(server_id)
    
    if not server.is_active:
        flash('Cannot deploy to inactive server. Please check the connection first.', 'error')
        return redirect(url_for('view_vps', server_id=server_id))
    
    if request.method == 'POST':
        domain = request.form.get('domain')
        is_wildcard = request.form.get('is_wildcard') == 'on'
        
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
        
        log_action('Deployment Started', f"Deploying to {domain} on {server.name}", server.id)
        
        success, result = deploy_project(server, password, domain, is_wildcard)
        
        if success:
            deployment.status = 'deployed'
            deployment.admin_url = f"https://{domain}/admin"
            flash(f'Project deployed successfully to {domain}!', 'success')
            
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
        else:
            deployment.status = 'failed'
            deployment.error_message = result
            flash(f'Deployment failed: {result}', 'error')
            
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
        
        db.session.commit()
        
        return redirect(url_for('view_vps', server_id=server_id))
    
    return render_template('deploy.html', server=server)


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
        ssh.exec_command("sudo systemctl reload apache2")
        
        import os
        local_project_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        upload_directory(sftp, local_project_path, f"/var/www/{domain}", ssh)
        
        ssh.exec_command(f"sudo mkdir -p /var/www/{domain}/page/result")
        ssh.exec_command(f"sudo chown -R www-data:www-data /var/www/{domain}")
        ssh.exec_command(f"sudo chmod -R 755 /var/www/{domain}")
        ssh.exec_command(f"sudo chmod -R 777 /var/www/{domain}/page/result")
        
        sftp.close()
        ssh.close()
        
        log_action('Deployment Complete', f"Successfully deployed to {domain}", server.id)
        return True, "Deployment successful"
        
    except Exception as e:
        log_action('Deployment Failed', f"Failed to deploy to {domain}: {str(e)}", server.id)
        return False, str(e)


def upload_directory(sftp, local_path, remote_path, ssh):
    import os
    
    exclude_dirs = ['vps_manager', '.git', '__pycache__', '.pythonlibs', '.upm', '.cache', 'node_modules']
    exclude_files = ['.gitignore', 'pyproject.toml', 'uv.lock', 'replit.md', '.replit', 'replit.nix']
    
    for item in os.listdir(local_path):
        if item in exclude_dirs or item in exclude_files or item.startswith('.'):
            continue
            
        local_item = os.path.join(local_path, item)
        remote_item = f"{remote_path}/{item}"
        
        if os.path.isfile(local_item):
            try:
                sftp.put(local_item, remote_item)
            except IOError:
                ssh.exec_command(f"sudo mkdir -p {os.path.dirname(remote_item)}")
                sftp.put(local_item, remote_item)
        elif os.path.isdir(local_item):
            try:
                sftp.stat(remote_item)
            except IOError:
                ssh.exec_command(f"sudo mkdir -p {remote_item}")
            upload_directory(sftp, local_item, remote_item, ssh)


@app.route('/vps/<int:server_id>/deployment/<int:deployment_id>/ssl', methods=['POST'])
def activate_ssl(server_id, deployment_id):
    server = VPSServer.query.get_or_404(server_id)
    deployment = Deployment.query.get_or_404(deployment_id)
    
    if not server.is_active:
        return jsonify({'success': False, 'message': 'Server is not active'})
    
    password = decrypt_password_safe(server.ssh_password)
    if password is None:
        return jsonify({'success': False, 'message': 'Failed to decrypt credentials'})
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server.ip_address, port=server.ssh_port, username=server.ssh_user, password=password, timeout=30)
        
        commands = [
            "sudo apt-get install -y certbot python3-certbot-apache",
        ]
        
        if deployment.is_wildcard:
            commands.append(f"sudo certbot --apache -d {deployment.domain} -d '*.{deployment.domain}' --non-interactive --agree-tos --email admin@{deployment.domain} --redirect")
        else:
            commands.append(f"sudo certbot --apache -d {deployment.domain} --non-interactive --agree-tos --email admin@{deployment.domain} --redirect")
        
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=300)
            stdout.channel.recv_exit_status()
        
        ssh.close()
        
        deployment.ssl_enabled = True
        deployment.admin_url = f"https://{deployment.domain}/admin"
        db.session.commit()
        
        log_action('SSL Activated', f"SSL enabled for {deployment.domain}", server.id)
        
        return jsonify({'success': True, 'message': 'SSL activated successfully', 'admin_url': deployment.admin_url})
        
    except Exception as e:
        log_action('SSL Failed', f"SSL activation failed for {deployment.domain}: {str(e)}", server.id)
        return jsonify({'success': False, 'message': str(e)})


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


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
