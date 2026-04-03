# HTTPS/WSS Setup Checklist for Ubuntu/Debian + Nginx

## Pre-Deployment Checklist

### Domain & DNS
- [ ] Domain name registered
- [ ] Domain DNS A record points to server IP address
- [ ] Domain DNS is propagated (run `dig yourdomain.com` to verify)
- [ ] Created a test subdomain (optional, for testing): api.yourdomain.com

### Server Preparation
- [ ] Ubuntu 20.04 LTS or Debian 11+ installed
- [ ] SSH access with sudo or root privileges
- [ ] Ports 80 (HTTP) and 443 (HTTPS) open in firewall
- [ ] Server has at least 10GB free disk space
- [ ] Server has at least 1GB RAM

### Local Preparation
- [ ] Code is ready and tested locally
- [ ] All environment variables documented
- [ ] Database schema prepared
- [ ] Backup of current code taken

---

## Deployment Steps (In Order)

### Phase 1: Domain & SSL Setup (5 minutes)
- [ ] Verify DNS resolution: `nslookup yourdomain.com`
- [ ] Run setup script with correct domain name
- [ ] **Command:**
  ```bash
  sudo bash setup-https-ubuntu.sh yourdomain.com admin@yourdomain.com
  ```
- [ ] Wait for script to complete
- [ ] Script should show:
  - ✅ Nginx configured
  - ✅ SSL certificate obtained
  - ✅ Backend service running

### Phase 2: Verify HTTPS Working (3 minutes)
- [ ] Test HTTP redirect:
  ```bash
  curl -I http://yourdomain.com
  # Should show: HTTP/1.1 301 Moved Permanently
  # Location: https://yourdomain.com
  ```
- [ ] Test HTTPS:
  ```bash
  curl -I https://yourdomain.com
  # Should show: HTTP/2 200 or 404 (frontend not deployed yet)
  ```
- [ ] Test API:
  ```bash
  curl https://yourdomain.com/api/
  # Should show either error or response from backend
  ```
- [ ] Check certificate:
  ```bash
  sudo certbot certificates
  # Should show certificate for yourdomain.com valid for ~90 days
  ```

### Phase 3: Deploy Frontend (5 minutes)
- [ ] SSH to server
- [ ] Navigate to frontend directory:
  ```bash
  cd /opt/securechat/frontend
  ```
- [ ] Update environment file:
  ```bash
  cat > .env << EOF
  VITE_API_URL=https://yourdomain.com
  EOF
  ```
- [ ] Build frontend:
  ```bash
  npm install
  npm run build
  ```
- [ ] Deploy built files:
  ```bash
  sudo mkdir -p /var/www/securechat
  sudo cp -r dist/* /var/www/securechat/
  sudo chown -R www-data:www-data /var/www/securechat
  ```
- [ ] Test frontend:
  ```bash
  curl -s https://yourdomain.com | head -c 200
  # Should show HTML content
  ```

### Phase 4: Verify Backend Running (3 minutes)
- [ ] Check backend service status:
  ```bash
  sudo systemctl status securechat-backend.service
  # Should show: active (running)
  ```
- [ ] Test backend API:
  ```bash
  curl -s https://yourdomain.com/api/ | head -c 100
  # Should return valid JSON response
  ```
- [ ] View backend logs:
  ```bash
  sudo journalctl -u securechat-backend.service -n 20
  # Should show no errors
  ```

### Phase 5: Test Full Application (10 minutes)
1. Open browser to: `https://yourdomain.com`
2. You should see the login page
3. Register a new account
   - [ ] Username accepted
   - [ ] No validation errors
   - [ ] Registration success message
4. Login with your account
   - [ ] Login successful
   - [ ] Redirected to chat page
   - [ ] "Connected" indicator shows
5. Test WebSocket connection:
   - [ ] Browser console should show: `✅ WebSocket connected`
   - [ ] No errors in console
6. Test key generation:
   - [ ] Keys generated message appears
   - [ ] Public keys published message
7. Create another account and test messaging
   - [ ] Register second account
   - [ ] Send chat request
   - [ ] Accept on other side
   - [ ] Send/receive messages

### Phase 6: Security Hardening (10 minutes)
- [ ] Update CORS_ORIGINS in backend (.env or systemd):
  ```bash
  sudo systemctl edit securechat-backend.service
  # Change CORS_ORIGINS to match your domain
  # Then:
  sudo systemctl restart securechat-backend.service
  ```
- [ ] Verify SSL redirect working:
  ```bash
  curl -v http://yourdomain.com/ 2>&1 | grep -i "301\|location"
  # Should show redirect to https
  ```
- [ ] Enable UFW firewall (if not already):
  ```bash
  sudo ufw allow 22   # SSH
  sudo ufw allow 80   # HTTP
  sudo ufw allow 443  # HTTPS
  sudo ufw enable
  ```
- [ ] Setup fail2ban:
  ```bash
  sudo apt-get install fail2ban
  sudo systemctl enable fail2ban
  sudo systemctl start fail2ban
  ```

---

## Post-Deployment (Do These Regularly)

### Daily
- [ ] Check service running: `sudo systemctl status securechat-backend.service`
- [ ] Monitor logs for errors: `sudo journalctl -u securechat-backend.service -n 50`

### Weekly
- [ ] Check disk space: `df -h`
- [ ] Check database size: `du -sh /opt/securechat/backend/chat.db`
- [ ] Verify HTTPS working: `curl -I https://yourdomain.com`

### Monthly
- [ ] Review security logs
- [ ] Check certificate expiration: `sudo certbot certificates`
- [ ] Backup database:
  ```bash
  sudo tar -czf /backups/securechat-$(date +%Y%m%d).tar.gz /opt/securechat/backend/chat.db
  ```
- [ ] Update system packages:
  ```bash
  sudo apt-get update
  sudo apt-get upgrade
  sudo systemctl restart securechat-backend.service
  ```

### Before Certificate Expiry (Auto-renewal handles this, but verify)
- [ ] Test renewal: `sudo certbot renew --dry-run`
- [ ] Check renewal is scheduled: `sudo systemctl list-timers | grep certbot`

---

## Troubleshooting Quick Reference

### "Connection refused" or WebSocket fails
```bash
# Check backend running
sudo systemctl status securechat-backend.service

# If not running, start it
sudo systemctl start securechat-backend.service

# View logs for errors
sudo journalctl -u securechat-backend.service -f
```

### "Bad gateway" errors
```bash
# Restart Nginx
sudo systemctl restart nginx

# Check Nginx config
sudo nginx -t

# View Nginx error log
sudo tail -50 /var/log/nginx/error.log
```

### SSL certificate issues
```bash
# Check certificate validity
sudo certbot certificates

# Renew manually if needed
sudo certbot renew --force-renewal

# Check Nginx is using correct certificate
sudo grep ssl_certificate /etc/nginx/sites-enabled/yourdomain.com
```

### Frontend not loading
```bash
# Check files exist
ls -la /var/www/securechat/index.html

# Check permissions
sudo chown -R www-data:www-data /var/www/securechat

# Reload Nginx
sudo systemctl reload nginx
```

### High CPU or memory usage
```bash
# Check what's using resources
top -o %CPU

# Check database size
du -sh /opt/securechat/backend/chat.db

# Restart backend to clear memory
sudo systemctl restart securechat-backend.service
```

---

## Quick Commands Reference

```bash
# Service Management
sudo systemctl start securechat-backend.service
sudo systemctl stop securechat-backend.service
sudo systemctl restart securechat-backend.service
sudo systemctl status securechat-backend.service

# Logs
sudo journalctl -u securechat-backend.service -f      # Follow logs
sudo journalctl -u securechat-backend.service -n 100  # Last 100 lines

# Nginx
sudo nginx -t                                    # Test config
sudo systemctl reload nginx                      # Reload without downtime
sudo tail -f /var/log/nginx/access.log          # View access logs
sudo tail -f /var/log/nginx/error.log           # View error logs

# SSL Certificates
sudo certbot certificates                         # List all certificates
sudo certbot renew --dry-run                     # Test auto-renewal
sudo certbot certificates --deploy-hook "systemctl reload nginx"

# System Info
df -h                                            # Disk usage
free -h                                          # RAM usage
ps aux | grep python                             # Find Python processes
netstat -tulpn | grep LISTEN                     # View listening ports

# Testing
curl -I https://yourdomain.com                   # Check HTTPS
curl -I http://yourdomain.com                    # Check HTTP->HTTPS redirect
curl -s https://yourdomain.com/api/ | jq .      # Test API with pretty JSON
```

---

## Success Indicators

✅ You're done when:

1. `curl https://yourdomain.com` returns HTML (frontend)
2. `curl https://yourdomain.com/api/` returns JSON (backend)
3. Browser shows no SSL warnings (green lock icon)
4. Login and registration work
5. Chat functionality works
6. WebSocket connects without errors
7. Certificate renewal is scheduled and working
8. Backend service auto-starts after reboot

---

## Next: Scaling & Optimization (Optional)

Once running, consider:

1. **Use PostgreSQL instead of SQLite**
   - Better for multiple concurrent users
   - Built-in replication for backups

2. **Add monitoring**
   - Prometheus + Grafana for metrics
   - AlertManager for notifications

3. **CDN for frontend**
   - Cloudflare (free tier available)
   - AWS CloudFront
   - Speeds up frontend delivery

4. **Database backups**
   - Automated daily backups
   - Store offsite (AWS S3, Azure Blob, etc.)

5. **Load balancing**
   - If expecting heavy traffic
   - Nginx upstream configuration

---

## Emergency Contacts/Notes

Record your setup information:

**Server Details:**
- Domain: ___________________
- IP Address: ___________________
- SSH User: ___________________
- Installation Path: /opt/securechat

**Certificate Info:**
- Issued By: Let's Encrypt
- Auto-renewal: Enabled
- Renewal Email: admin@yourdomain.com

**Support Resources:**
- Let's Encrypt Docs: https://letsencrypt.org/docs/
- Nginx Docs: https://nginx.org/en/docs/
- FastAPI Docs: https://fastapi.tiangolo.com/

---

**Last Updated:** April 3, 2026

