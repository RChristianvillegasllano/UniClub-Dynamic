# Hostinger VPS Deployment Guide

Complete step-by-step instructions for deploying the UniClub Management System on Hostinger VPS.

---

## 📋 Prerequisites

Before starting, ensure you have:
- ✅ Hostinger VPS purchased and activated
- ✅ SSH access credentials (IP address, username, password/SSH key)
- ✅ Domain name (optional but recommended)
- ✅ Basic knowledge of Linux commands
- ✅ Your application code ready to deploy

---

## 🚀 Step 1: Initial VPS Setup

### 1.1 Connect to Your VPS

**On Windows (PowerShell/Command Prompt):**
```bash
ssh root@your-vps-ip-address
# Or if using a different user:
ssh username@your-vps-ip-address
```

**On Mac/Linux:**
```bash
ssh root@your-vps-ip-address
```

Enter your password when prompted.

### 1.2 Update System Packages

```bash
# For Ubuntu/Debian
sudo apt update && sudo apt upgrade -y

# For CentOS/RHEL
sudo yum update -y
```

### 1.3 Create a Non-Root User (Recommended)

```bash
# Create a new user
adduser uniclub
usermod -aG sudo uniclub

# Switch to the new user
su - uniclub
```

---

## 🗄️ Step 2: Install Required Software

### 2.1 Install Node.js (v18 or higher recommended)

```bash
# Using NodeSource repository (recommended)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installation
node --version
npm --version
```

### 2.2 Install MySQL Server

```bash
# Install MySQL
sudo apt install mysql-server -y

# Secure MySQL installation
sudo mysql_secure_installation

# Start and enable MySQL
sudo systemctl start mysql
sudo systemctl enable mysql
```

**During MySQL secure installation, you'll be asked:**
- Set root password? **Yes** (choose a strong password)
- Remove anonymous users? **Yes**
- Disallow root login remotely? **Yes** (unless you need remote access)
- Remove test database? **Yes**
- Reload privilege tables? **Yes**

### 2.3 Install Nginx (Web Server & Reverse Proxy)

```bash
sudo apt install nginx -y

# Start and enable Nginx
sudo systemctl start nginx
sudo systemctl enable nginx

# Check status
sudo systemctl status nginx
```

### 2.4 Install PM2 (Process Manager)

```bash
# Install PM2 globally
sudo npm install -g pm2

# Verify installation
pm2 --version
```

### 2.5 Install Git (if not already installed)

```bash
sudo apt install git -y
```

---

## 📦 Step 3: Deploy Your Application

### 3.1 Create Application Directory

```bash
# Create directory for your application
sudo mkdir -p /var/www/uniclub
sudo chown -R $USER:$USER /var/www/uniclub
cd /var/www/uniclub
```

### 3.2 Upload Your Application Code

**Option A: Using Git (Recommended)**
```bash
# Clone your repository
git clone https://github.com/your-username/your-repo.git .

# Or if you have a private repo, use SSH
git clone git@github.com:your-username/your-repo.git .
```

**Option B: Using SCP (from your local machine)**
```bash
# From your local machine (Windows PowerShell)
scp -r D:\rchri\Documents\UNICLUB-DYNAMIC\uniclub-express\* root@your-vps-ip:/var/www/uniclub/

# From your local machine (Mac/Linux)
scp -r /path/to/uniclub-express/* root@your-vps-ip:/var/www/uniclub/
```

**Option C: Using SFTP Client (FileZilla, WinSCP, etc.)**
- Connect via SFTP to your VPS
- Navigate to `/var/www/uniclub`
- Upload all files from `uniclub-express` folder

### 3.3 Install Dependencies

```bash
cd /var/www/uniclub
npm install --production
```

---

## 🗄️ Step 4: Set Up MySQL Database

### 4.1 Create Database and User

```bash
# Login to MySQL
sudo mysql -u root -p

# In MySQL prompt, run:
CREATE DATABASE Uniclub CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'uniclub_user'@'localhost' IDENTIFIED BY 'your_strong_password_here';
GRANT ALL PRIVILEGES ON Uniclub.* TO 'uniclub_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

**⚠️ Important:** Replace `your_strong_password_here` with a strong password.

### 4.2 Import Database Schema

```bash
# If you have a SQL file
cd /var/www/uniclub
mysql -u uniclub_user -p Uniclub < sql/Uniclub.sql

# Or if you need to create tables manually, you can run the SQL file
mysql -u uniclub_user -p Uniclub < sql/create_finance_tables.sql
```

---

## ⚙️ Step 5: Configure Environment Variables

### 5.1 Create .env File

```bash
cd /var/www/uniclub
nano .env
```

### 5.2 Add Environment Variables

Copy and paste the following, then modify with your actual values:

```env
# Node Environment
NODE_ENV=production
PORT=3000

# Session Secret (generate a random string)
SESSION_SECRET=your_very_long_random_secret_key_here_minimum_32_characters

# Database Configuration
DB_HOST=localhost
DB_USER=uniclub_user
DB_PASSWORD=your_strong_password_here
DB_NAME=Uniclub
DB_PORT=3306

# Or use connection string format:
# DATABASE_URL=mysql://uniclub_user:your_strong_password_here@localhost:3306/Uniclub

# Email Configuration (SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-specific-password
EMAIL_FROM="UniClub System <your-email@gmail.com>"

# CORS (if needed)
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# CSRF (optional - for development)
# CSRF_DISABLED=false
```

**To generate a secure SESSION_SECRET:**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**For Gmail SMTP:**
1. Enable 2-Factor Authentication on your Google account
2. Generate an App Password: https://myaccount.google.com/apppasswords
3. Use the generated app password in `SMTP_PASS`

**Save and exit:** Press `Ctrl+X`, then `Y`, then `Enter`

### 5.3 Secure .env File

```bash
# Set proper permissions (only owner can read/write)
chmod 600 .env
```

---

## 🔧 Step 6: Configure Nginx as Reverse Proxy

### 6.1 Create Nginx Configuration

```bash
sudo nano /etc/nginx/sites-available/uniclub
```

### 6.2 Add Configuration

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    # If you don't have a domain yet, use your VPS IP
    # server_name your-vps-ip-address;

    # Logs
    access_log /var/log/nginx/uniclub-access.log;
    error_log /var/log/nginx/uniclub-error.log;

    # Maximum upload size
    client_max_body_size 10M;

    # Proxy to Node.js application
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Serve static files directly (optional optimization)
    location /public {
        alias /var/www/uniclub/public;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

**Save and exit:** Press `Ctrl+X`, then `Y`, then `Enter`

### 6.3 Enable Site

```bash
# Create symbolic link
sudo ln -s /etc/nginx/sites-available/uniclub /etc/nginx/sites-enabled/

# Remove default site (optional)
sudo rm /etc/nginx/sites-enabled/default

# Test Nginx configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

---

## 🔒 Step 7: Set Up SSL Certificate (HTTPS)

### 7.1 Install Certbot

```bash
sudo apt install certbot python3-certbot-nginx -y
```

### 7.2 Obtain SSL Certificate

**If you have a domain:**
```bash
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

**If you don't have a domain yet:**
- You can skip this step for now
- Access your site via HTTP: `http://your-vps-ip`
- Set up SSL later when you have a domain

**Follow the prompts:**
- Enter your email address
- Agree to terms
- Choose whether to redirect HTTP to HTTPS (recommended: Yes)

### 7.3 Auto-Renewal

Certbot automatically sets up auto-renewal. Test it:
```bash
sudo certbot renew --dry-run
```

---

## 🚀 Step 8: Start Application with PM2

### 8.1 Start Application

```bash
cd /var/www/uniclub
pm2 start server.js --name uniclub
```

### 8.2 Configure PM2 to Start on Boot

```bash
# Generate startup script
pm2 startup

# Save PM2 process list
pm2 save
```

### 8.3 Useful PM2 Commands

```bash
# View running processes
pm2 list

# View logs
pm2 logs uniclub

# Restart application
pm2 restart uniclub

# Stop application
pm2 stop uniclub

# Monitor application
pm2 monit
```

---

## 🔥 Step 9: Configure Firewall

### 9.1 Set Up UFW (Uncomplicated Firewall)

```bash
# Allow SSH (important - do this first!)
sudo ufw allow OpenSSH

# Allow HTTP
sudo ufw allow 'Nginx Full'

# Or allow specific ports:
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
```

**⚠️ Important:** Make sure to allow SSH before enabling the firewall, or you might lock yourself out!

---

## ✅ Step 10: Verify Deployment

### 10.1 Check Application Status

```bash
# Check PM2
pm2 status

# Check Nginx
sudo systemctl status nginx

# Check MySQL
sudo systemctl status mysql

# Check application logs
pm2 logs uniclub --lines 50
```

### 10.2 Test Application

1. **If you have a domain:** Visit `https://yourdomain.com`
2. **If using IP:** Visit `http://your-vps-ip`

### 10.3 Create Admin Account

```bash
cd /var/www/uniclub
npm run create-admin
```

Follow the prompts to create your first admin account.

---

## 🔧 Step 11: Set Up Automated Backups

### 11.1 Create Backup Script

```bash
nano /var/www/uniclub/scripts/backup.sh
```

Add the following:

```bash
#!/bin/bash

# Backup configuration
BACKUP_DIR="/var/backups/uniclub"
DB_USER="uniclub_user"
DB_NAME="Uniclub"
DB_PASSWORD="your_strong_password_here"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
mysqldump -u $DB_USER -p$DB_PASSWORD $DB_NAME | gzip > $BACKUP_DIR/db_backup_$DATE.sql.gz

# Backup application files (optional)
tar -czf $BACKUP_DIR/app_backup_$DATE.tar.gz /var/www/uniclub --exclude=/var/www/uniclub/node_modules

# Keep only last 7 days of backups
find $BACKUP_DIR -name "*.sql.gz" -mtime +7 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: $DATE"
```

**Make it executable:**
```bash
chmod +x /var/www/uniclub/scripts/backup.sh
```

### 11.2 Set Up Cron Job

```bash
# Edit crontab
crontab -e

# Add this line to run backup daily at 2 AM
0 2 * * * /var/www/uniclub/scripts/backup.sh >> /var/log/uniclub-backup.log 2>&1
```

---

## 📊 Step 12: Monitoring & Maintenance

### 12.1 Monitor System Resources

```bash
# Check disk space
df -h

# Check memory usage
free -h

# Check CPU usage
top
# Press 'q' to exit

# Check application logs
pm2 logs uniclub
```

### 12.2 Update Application

```bash
cd /var/www/uniclub

# Pull latest changes (if using Git)
git pull origin main

# Install new dependencies
npm install --production

# Restart application
pm2 restart uniclub
```

### 12.3 Update System Packages

```bash
# Update system packages monthly
sudo apt update && sudo apt upgrade -y
```

---

## 🐛 Troubleshooting

### Application Won't Start

```bash
# Check PM2 logs
pm2 logs uniclub --err

# Check if port is in use
sudo netstat -tulpn | grep 3000

# Check environment variables
cd /var/www/uniclub
cat .env
```

### Database Connection Issues

```bash
# Test MySQL connection
mysql -u uniclub_user -p Uniclub

# Check MySQL status
sudo systemctl status mysql

# Check MySQL logs
sudo tail -f /var/log/mysql/error.log
```

### Nginx Issues

```bash
# Test Nginx configuration
sudo nginx -t

# Check Nginx logs
sudo tail -f /var/log/nginx/uniclub-error.log

# Restart Nginx
sudo systemctl restart nginx
```

### Permission Issues

```bash
# Fix ownership
sudo chown -R $USER:$USER /var/www/uniclub

# Fix permissions
chmod -R 755 /var/www/uniclub
chmod 600 /var/www/uniclub/.env
```

### Port Already in Use

```bash
# Find process using port 3000
sudo lsof -i :3000

# Kill the process (replace PID with actual process ID)
sudo kill -9 PID
```

---

## 🔐 Security Checklist

- [ ] Changed default SSH port (optional but recommended)
- [ ] Set up SSH key authentication (disable password auth)
- [ ] Configured firewall (UFW)
- [ ] Set strong database passwords
- [ ] Set secure SESSION_SECRET
- [ ] Configured SSL/HTTPS
- [ ] Set proper file permissions (.env is 600)
- [ ] Enabled automatic security updates
- [ ] Set up regular backups
- [ ] Configured fail2ban (optional but recommended)

### Additional Security (Optional)

**Install Fail2ban:**
```bash
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

**Enable Automatic Security Updates:**
```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
```

---

## 📝 Environment Variables Reference

Here's a complete list of environment variables your application uses:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `NODE_ENV` | Yes | Environment mode | `production` |
| `PORT` | No | Server port (default: 3000) | `3000` |
| `SESSION_SECRET` | Yes | Secret for session encryption | `long_random_string` |
| `DB_HOST` | Yes | Database host | `localhost` |
| `DB_USER` | Yes | Database username | `uniclub_user` |
| `DB_PASSWORD` | Yes | Database password | `strong_password` |
| `DB_NAME` | Yes | Database name | `Uniclub` |
| `DB_PORT` | No | Database port (default: 3306) | `3306` |
| `SMTP_HOST` | No* | SMTP server host | `smtp.gmail.com` |
| `SMTP_PORT` | No* | SMTP port | `587` |
| `SMTP_SECURE` | No* | Use SSL/TLS | `false` |
| `SMTP_USER` | No* | SMTP username | `your-email@gmail.com` |
| `SMTP_PASS` | No* | SMTP password | `app_password` |
| `EMAIL_FROM` | No* | Email sender | `"UniClub System <email@example.com>"` |
| `ALLOWED_ORIGINS` | No | CORS allowed origins | `https://yourdomain.com` |

*Required only if you need email functionality (password reset, OTP)

---

## 🌐 Domain Configuration (If You Have a Domain)

### DNS Settings

In your domain registrar's DNS settings, add:

**A Record:**
- Type: `A`
- Name: `@` (or leave blank)
- Value: `your-vps-ip-address`
- TTL: `3600` (or default)

**A Record (for www):**
- Type: `A`
- Name: `www`
- Value: `your-vps-ip-address`
- TTL: `3600` (or default)

Wait for DNS propagation (can take up to 48 hours, usually 1-2 hours).

---

## 📞 Support Resources

- **Hostinger Support:** https://www.hostinger.com/contact
- **PM2 Documentation:** https://pm2.keymetrics.io/docs/
- **Nginx Documentation:** https://nginx.org/en/docs/
- **Node.js Documentation:** https://nodejs.org/docs/

---

## 🎉 You're Done!

Your UniClub Management System should now be running on your Hostinger VPS!

**Access your application:**
- With domain: `https://yourdomain.com`
- Without domain: `http://your-vps-ip`

**Next Steps:**
1. Create your admin account: `npm run create-admin`
2. Test all functionality
3. Set up monitoring alerts
4. Schedule regular backups
5. Review security settings

---

**Last Updated:** 2025-01-10
**Version:** 1.0

