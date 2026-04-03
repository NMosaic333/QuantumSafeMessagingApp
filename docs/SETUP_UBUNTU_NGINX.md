# Ubuntu/Debian + Nginx Setup Guide

## Quick Reference

**This is the fastest way to get HTTPS/WSS running on Ubuntu/Debian with Nginx.**

### Prerequisites
- Ubuntu 20.04 LTS or later (or Debian 11+)
- A domain name pointing to your server
- SSH access to your server as root or with sudo
- Ports 80 and 443 open to the internet

### One-Command Setup

```bash
# Download and run setup script
cd /tmp
wget https://raw.githubusercontent.com/yourusername/ipd-project/main/scripts/setup-https-ubuntu.sh
sudo bash setup-https-ubuntu.sh yourdomain.com admin@yourdomain.com
```

**That's it!** The script will:
- ✅ Install Nginx, certbot, Python, and dependencies
- ✅ Configure SSL with Let's Encrypt
- ✅ Set up Nginx reverse proxy
- ✅ Create systemd service for backend
- ✅ Enable auto-renewal
- ✅ Configure security headers

---

## Manual Step-by-Step Setup (if you prefer)

### Step 1: Update System

```bash
sudo apt-get update
sudo apt-get upgrade -y
```

### Step 2: Install Required Packages

```bash
sudo apt-get install -y \
  nginx \
  certbot \
  python3-certbot-nginx \
  python3-pip \
  python3-venv \
  git \
  curl
```

### Step 3: Clone/Deploy Your Application

```bash
sudo mkdir -p /opt/securechat
cd /opt/securechat
sudo git clone https://github.com/yourusername/ipd-project.git .
# Or copy your code manually
```

### Step 4: Setup Backend

```bash
cd /opt/securechat/backend
sudo python3 -m venv venv
sudo source venv/bin/activate
sudo pip install -r requirements.txt
```

### Step 5: Get SSL Certificate

```bash
sudo certbot certonly --nginx \
  -d yourdomain.com \
  -d www.yourdomain.com \
  --agree-tos \
  --email admin@yourdomain.com \
  --non-interactive
```

### Step 6: Configure Nginx

Create `/etc/nginx/sites-available/yourdomain.com`:

```nginx
# HTTP redirect to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name yourdomain.com www.yourdomain.com;
    
    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;

    # Backend proxy
    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket
    location /ws/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }

    # Frontend
    location / {
        root /var/www/securechat;
        try_files $uri $uri/ /index.html;
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/yourdomain.com /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t  # Test config
sudo systemctl reload nginx
```

### Step 7: Create Systemd Service

Create `/etc/systemd/system/securechat-backend.service`:

```ini
[Unit]
Description=SecureChat Backend API
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/securechat/backend
ExecStart=/opt/securechat/backend/venv/bin/python -m app.main
Restart=on-failure
RestartSec=10s
Environment="DATABASE_URL=sqlite:////opt/securechat/backend/chat.db"
Environment="CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com"

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable securechat-backend.service
sudo systemctl start securechat-backend.service
```

### Step 8: Build and Deploy Frontend

```bash
cd /opt/securechat/frontend
npm install
npm run build
sudo mkdir -p /var/www/securechat
sudo cp -r dist/* /var/www/securechat/
sudo chown -R www-data:www-data /var/www/securechat
```

Update `.env` before building:
```
VITE_API_URL=https://yourdomain.com
```

---

## Verification

### Check Services Running

```bash
# Backend
sudo systemctl status securechat-backend.service

# Nginx
sudo systemctl status nginx

# Check listening ports
sudo netstat -tulpn | grep LISTEN
```

### Test HTTPS

```bash
# Test HTTP redirect
curl -I http://yourdomain.com

# Test HTTPS
curl -I https://yourdomain.com

# Test API
curl -I https://yourdomain.com/api/

# Test WebSocket (should show upgrade headers)
curl -I -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  https://yourdomain.com/ws/testuser?token=testtoken
```

### View Logs

```bash
# Backend logs
sudo journalctl -u securechat-backend.service -f

# Nginx access logs
sudo tail -f /var/log/nginx/access.log

# Nginx error logs
sudo tail -f /var/log/nginx/error.log

# Certbot renewal logs
sudo tail -f /var/log/letsencrypt/renewal.log
```

---

## Auto-Renewal Setup

Certbot automatically handles renewal, but verify:

```bash
# Check certificates
sudo certbot certificates

# Test renewal (dry run)
sudo certbot renew --dry-run

# View renewal cron job
sudo systemctl status certbot.timer

# Or check renewal service
sudo systemctl list-timers --all | grep certbot
```

---

## Monitoring & Maintenance

### Monitor Certificate Expiration

```bash
# Check expiration
sudo certbot certificates

# Get alerts automatically
# Certbot email: admin@yourdomain.com (from setup)
```

### Monitor Service Health

```bash
# Check if backend is running
sudo systemctl is-active securechat-backend.service

# Check if responsive
curl -s https://yourdomain.com/api/ | head -c 100

# Monitor resource usage
top
free -h
df -h
```

### Update Application

```bash
cd /opt/securechat/backend
sudo -u www-data source venv/bin/activate
sudo -u www-data pip install -r requirements.txt

# Restart backend
sudo systemctl restart securechat-backend.service
```

---

## Troubleshooting

### Nginx Not Reloading

```bash
# Check syntax
sudo nginx -t

# View detailed error
sudo systemctl status nginx -l

# Reload verbose
sudo systemctl reload nginx
```

### WebSocket Connection Issues

**Check 1: Verify proxy headers in Nginx**
```bash
sudo grep -A 5 "location /ws/" /etc/nginx/sites-enabled/yourdomain.com
```

**Check 2: Check backend is running**
```bash
sudo systemctl status securechat-backend.service
curl -v http://localhost:8000/
```

**Check 3: Check firewall**
```bash
sudo ufw allow 443  # HTTPS
sudo ufw allow 80   # HTTP
sudo ufw status
```

**Check 4: View backend logs**
```bash
sudo journalctl -u securechat-backend.service -n 50
```

### SSL Certificate Issues

```bash
# Check certificate validity
sudo certbot certificates

# Check file permissions
sudo ls -la /etc/letsencrypt/live/yourdomain.com/

# Verify certificate matches key
sudo openssl x509 -noout -modulus -in /etc/letsencrypt/live/yourdomain.com/fullchain.pem | openssl md5
sudo openssl rsa -noout -modulus -in /etc/letsencrypt/live/yourdomain.com/privkey.pem | openssl md5
```

### Performance Issues

```bash
# Check system resources
free -h           # RAM usage
df -h             # Disk usage
top -o %CPU       # CPU usage

# Check Nginx worker processes
ps aux | grep nginx

# Check database file size
du -sh /opt/securechat/backend/chat.db
```

### Database Issues

```bash
# Check database exists
ls -lah /opt/securechat/backend/chat.db

# Reset database (CAREFUL!)
rm /opt/securechat/backend/chat.db
sudo systemctl restart securechat-backend.service
```

---

## Security Checklist

- [ ] HTTPS/WSS enabled
- [ ] Security headers configured (HSTS, CSP, etc.)
- [ ] Certificate auto-renewal working
- [ ] Backend not exposed directly (only through Nginx)
- [ ] Database backups scheduled
- [ ] Firewall configured (ufw)
- [ ] Fail2ban installed for bruteforce protection
- [ ] Log rotation configured
- [ ] Monitor disk space

---

## Next Steps

1. **Install Fail2ban** for additional security:
   ```bash
   sudo apt-get install fail2ban
   sudo systemctl enable fail2ban
   ```

2. **Setup log rotation** for /opt/securechat/backend logs

3. **Backup strategy**:
   ```bash
   # Backup database periodically
   sudo tar -czf /backups/securechat-$(date +%Y%m%d).tar.gz /opt/securechat/
   ```

4. **Monitor with**:
   - New Relic, Datadog, or similar
   - Basic: `top`, `htop`, `iotop`

5. **Rate limiting at Nginx level** (optional):
   ```nginx
   limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
   limit_req zone=api burst=20 nodelay;
   ```

---

## Support

If you encounter issues:

1. Check service status: `sudo systemctl status securechat-backend.service`
2. View logs: `sudo journalctl -u securechat-backend.service -f`
3. Check Nginx: `sudo nginx -t && sudo systemctl reload nginx`
4. Verify SSL: `curl -v https://yourdomain.com`

