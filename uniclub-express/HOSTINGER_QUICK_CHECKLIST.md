# Hostinger VPS Deployment - Quick Checklist

Use this checklist during deployment to track your progress.

## Pre-Deployment
- [ ] VPS purchased and activated
- [ ] SSH access credentials ready
- [ ] Domain name configured (optional)
- [ ] Application code ready

## Initial Setup
- [ ] Connected to VPS via SSH
- [ ] Updated system packages (`sudo apt update && sudo apt upgrade -y`)
- [ ] Created non-root user (optional but recommended)

## Software Installation
- [ ] Node.js installed (v18+)
- [ ] MySQL installed and secured
- [ ] Nginx installed
- [ ] PM2 installed globally
- [ ] Git installed

## Application Deployment
- [ ] Application directory created (`/var/www/uniclub`)
- [ ] Application code uploaded
- [ ] Dependencies installed (`npm install --production`)

## Database Setup
- [ ] MySQL database created (`Uniclub`)
- [ ] Database user created with privileges
- [ ] Database schema imported
- [ ] Database connection tested

## Configuration
- [ ] `.env` file created with all required variables
- [ ] `SESSION_SECRET` generated (32+ characters)
- [ ] Database credentials configured
- [ ] Email/SMTP configured (if needed)
- [ ] `.env` file permissions set to 600

## Web Server (Nginx)
- [ ] Nginx configuration file created
- [ ] Site enabled (`ln -s`)
- [ ] Nginx configuration tested (`nginx -t`)
- [ ] Nginx reloaded/restarted

## SSL Certificate
- [ ] Certbot installed
- [ ] SSL certificate obtained (if domain available)
- [ ] Auto-renewal configured
- [ ] HTTPS redirect working

## Application Startup
- [ ] Application started with PM2
- [ ] PM2 startup script configured
- [ ] PM2 process list saved
- [ ] Application accessible via browser

## Security
- [ ] Firewall (UFW) configured
- [ ] SSH access allowed
- [ ] HTTP/HTTPS ports allowed
- [ ] Strong passwords set
- [ ] File permissions correct

## Backups
- [ ] Backup script created
- [ ] Backup script executable
- [ ] Cron job configured for daily backups
- [ ] Backup tested manually

## Final Verification
- [ ] Application loads in browser
- [ ] Admin account created (`npm run create-admin`)
- [ ] Login functionality works
- [ ] Database operations work
- [ ] File uploads work (if applicable)
- [ ] Email sending works (if configured)

## Monitoring
- [ ] PM2 monitoring set up
- [ ] Log locations noted
- [ ] System resource monitoring configured
- [ ] Update procedures documented

## Post-Deployment
- [ ] DNS propagation verified (if using domain)
- [ ] SSL certificate verified
- [ ] All features tested
- [ ] Documentation reviewed
- [ ] Team notified of deployment

---

## Quick Commands Reference

```bash
# Application Management
pm2 start server.js --name uniclub
pm2 restart uniclub
pm2 stop uniclub
pm2 logs uniclub
pm2 list

# Service Management
sudo systemctl status nginx
sudo systemctl restart nginx
sudo systemctl status mysql
sudo systemctl restart mysql

# Database
mysql -u uniclub_user -p Uniclub
mysqldump -u uniclub_user -p Uniclub > backup.sql

# Logs
pm2 logs uniclub
sudo tail -f /var/log/nginx/uniclub-error.log
sudo tail -f /var/log/nginx/uniclub-access.log

# Testing
curl http://localhost:3000
sudo nginx -t
```

---

**Note:** Check the full guide (`HOSTINGER_VPS_DEPLOYMENT.md`) for detailed instructions on each step.

