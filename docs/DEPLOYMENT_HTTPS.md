# HTTPS/WSS Deployment Guide

## Overview

For a production deployment, **all traffic must be encrypted using HTTPS and WSS (WebSocket Secure)**. This guide covers setting up SSL/TLS certificates and configuring your application for secure communications.

---

## Option 1: Using Let's Encrypt with Certbot (Recommended for Production)

### Prerequisites
- A domain name pointing to your server
- Server running Linux (Ubuntu/Debian recommended)
- Port 80 and 443 open to the internet

### Step 1: Install Certbot

```bash
sudo apt update
sudo apt install certbot python3-certbot-nginx  # or python3-certbot-apache
```

### Step 2: Obtain a Certificate

```bash
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com
```

The certificate will be saved to:
- **Certificate file:** `/etc/letsencrypt/live/yourdomain.com/fullchain.pem`
- **Private key:** `/etc/letsencrypt/live/yourdomain.com/privkey.pem`

### Step 3: Configure Backend for HTTPS

Install SSL/TLS support for FastAPI:

```bash
pip install python-multipart uvicorn[standard]
```

Update [backend/app/main.py](backend/app/main.py) startup to use SSL:

```python
if __name__ == "__main__":
    import ssl
    
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile="/etc/letsencrypt/live/yourdomain.com/fullchain.pem",
        keyfile="/etc/letsencrypt/live/yourdomain.com/privkey.pem"
    )
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=443,
        ssl_keyfile="/etc/letsencrypt/live/yourdomain.com/privkey.pem",
        ssl_certfile="/etc/letsencrypt/live/yourdomain.com/fullchain.pem",
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
        ssl_cert_reqs=ssl.CERT_NONE,
        ssl_ca_certs=None,
        loop="uvloop"
    )
```

Or simpler with uvicorn CLI:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 443 \
  --ssl-keyfile=/etc/letsencrypt/live/yourdomain.com/privkey.pem \
  --ssl-certfile=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
```

### Step 4: Configure Frontend for WSS

Update your environment files:

```env
# frontend/.env
VITE_API_URL=https://yourdomain.com
```

The frontend automatically converts `https://` to `wss://` for WebSocket connections (see [App.jsx](../frontend/src/App.jsx)).

### Step 5: Auto-Renewal

Let's Encrypt certificates expire after 90 days. Set up automatic renewal:

```bash
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# Test renewal
sudo certbot renew --dry-run
```

---

## Option 2: Using Nginx as Reverse Proxy (Best Practice)

This approach is more robust and easier to manage.

### Step 1: Install Nginx and Certbot

```bash
sudo apt update
sudo apt install nginx certbot python3-certbot-nginx
```

### Step 2: Create SSL Certificate

```bash
sudo certbot certonly --nginx -d yourdomain.com -d www.yourdomain.com
```

### Step 3: Configure Nginx

Create `/etc/nginx/sites-available/securechat`:

```nginx
# Redirect HTTP to HTTPS
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

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Backend API (Python/FastAPI on port 8000)
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

    # WebSocket endpoint
    location /ws/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;  # Allow long-lived WebSocket connections
    }

    # Serve frontend React app
    location / {
        root /var/www/securechat/dist;
        try_files $uri $uri/ /index.html;
    }
}
```

### Step 4: Enable the Site

```bash
sudo ln -s /etc/nginx/sites-available/securechat /etc/nginx/sites-enabled/
sudo nginx -t  # Test configuration
sudo systemctl restart nginx
```

### Step 5: Build and Deploy Frontend

```bash
cd frontend
npm run build
sudo cp -r dist/* /var/www/securechat/dist/
```

### Step 6: Start Backend (Running on port 8000, proxied through Nginx)

```bash
cd backend
python -m app.main
```

---

## Option 3: Docker Deployment with Let's Encrypt

### Create docker-compose.yml

```yaml
version: '3.8'

services:
  backend:
    build: ./backend
    container_name: securechat-backend
    environment:
      - DATABASE_URL=sqlite:///./chat.db
      - CORS_ORIGINS=https://yourdomain.com
    volumes:
      - ./backend/chat.db:/app/chat.db
    ports:
      - "8000:8000"
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000

  frontend:
    build: ./frontend
    container_name: securechat-frontend
    environment:
      - VITE_API_URL=https://yourdomain.com
    ports:
      - "3000:3000"

  nginx:
    image: nginx:latest
    container_name: securechat-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
    depends_on:
      - backend
      - frontend
```

---

## Testing HTTPS/WSS Locally (Development)

For testing without a real domain, use self-signed certificates:

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

# Run with self-signed cert
uvicorn app.main:app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile=key.pem \
  --ssl-certfile=cert.pem
```

**Note:** Browsers will warn about self-signed certificates. This is normal for development.

---

## Security Best Practices

1. **Always use HTTPS in production** - No exceptions
2. **Keep certificates up to date** - Set up auto-renewal
3. **Use strong TLS versions** - TLSv1.2 minimum, TLSv1.3 preferred
4. **Enable HSTS** - Enforce HTTPS with Strict-Transport-Security header
5. **Monitor certificate expiration** - Set calendar reminders
6. **Use a WAF** - Consider Cloudflare or AWS WAF for additional protection

---

## Troubleshooting

### Certificate Issues

```bash
# Check certificate validity
openssl x509 -in /etc/letsencrypt/live/yourdomain.com/fullchain.pem -text -noout

# Test SSL configuration
curl -v https://yourdomain.com/api/

# Check Nginx logs
sudo tail -f /var/log/nginx/error.log
```

### WebSocket Connection Issues

```javascript
// Browser console - check WebSocket connection
const ws = new WebSocket('wss://yourdomain.com/ws/username?token=...');
ws.addEventListener('error', (event) => console.log('WebSocket error:', event));
ws.addEventListener('open', () => console.log('WebSocket connected'));
```

### CORS Issues with HTTPS

Make sure `CORS_ORIGINS` environment variable includes your domain:

```bash
export CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

---

## Next Steps

After deploying with HTTPS/WSS:

- Monitor certificate expiration dates
- Review and rotate API keys regularly
- Implement rate limiting at the infrastructure level
- Consider adding a firewall/WAF
- Set up monitoring and alerting
- Perform a security audit
- Consider a CDN for static content (frontend)

