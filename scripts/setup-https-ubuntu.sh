#!/bin/bash
# QuantumSafeMessagingApp - HTTPS/WSS Setup Script for Ubuntu/Debian
# This script automates the setup of HTTPS/WSS with Let's Encrypt and Nginx
# 
# Usage: sudo bash setup-https.sh yourdomain.com

set -e

DOMAIN=${1:-example.com}
EMAIL=${2:-admin@${DOMAIN}}
APP_DIR="/opt/securechat"
BACKEND_PORT=8000
FRONTEND_PORT=3000

echo "========================================"
echo "SecureChat HTTPS/WSS Setup"
echo "========================================"
echo "Domain: $DOMAIN"
echo "Email: $EMAIL"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

echo -e "${YELLOW}[1/7] Updating system packages...${NC}"
apt-get update
apt-get upgrade -y

echo -e "${YELLOW}[2/7] Installing dependencies...${NC}"
apt-get install -y \
  nginx \
  certbot \
  python3-certbot-nginx \
  python3-pip \
  python3-venv \
  git \
  curl \
  wget \
  supervisor

echo -e "${YELLOW}[3/7] Creating application directory...${NC}"
mkdir -p $APP_DIR
cd $APP_DIR

echo -e "${YELLOW}[4/7] Setting up backend...${NC}"
if [ ! -d "backend" ]; then
  echo "Please copy your backend directory to $APP_DIR/backend and run this script again"
  exit 1
fi

cd $APP_DIR/backend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo -e "${YELLOW}[5/7] Getting SSL certificate from Let's Encrypt...${NC}"
certbot certonly --nginx -d $DOMAIN -d www.$DOMAIN --agree-tos --email $EMAIL --non-interactive

echo -e "${YELLOW}[6/7] Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/$DOMAIN << 'NGINX_CONFIG'
# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name DOMAIN_PLACEHOLDER www.DOMAIN_PLACEHOLDER;
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    
    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name DOMAIN_PLACEHOLDER www.DOMAIN_PLACEHOLDER;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;

    client_max_body_size 100M;

    # API endpoints
    location /api/ {
        proxy_pass http://localhost:BACKEND_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
    }

    # WebSocket endpoint - CRITICAL for long-lived connections
    location /ws/ {
        proxy_pass http://localhost:BACKEND_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Important for long-lived WebSocket connections
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_connect_timeout 7d;
        
        proxy_buffering off;
    }

    # Frontend (React app)
    location / {
        root /var/www/securechat;
        try_files $uri $uri/ /index.html;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
}
NGINX_CONFIG

# Replace placeholders
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" /etc/nginx/sites-available/$DOMAIN
sed -i "s/BACKEND_PORT/$BACKEND_PORT/g" /etc/nginx/sites-available/$DOMAIN

# Enable site
ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration
nginx -t

# Reload Nginx
systemctl reload nginx

echo -e "${YELLOW}[7/7] Setting up systemd service for backend...${NC}"
cat > /etc/systemd/system/securechat-backend.service << SERVICE_CONFIG
[Unit]
Description=SecureChat Backend API
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=$APP_DIR/backend
ExecStart=$APP_DIR/backend/venv/bin/python -m app.main
Restart=on-failure
RestartSec=10s
Environment="DATABASE_URL=sqlite:///$APP_DIR/backend/chat.db"
Environment="CORS_ORIGINS=https://$DOMAIN,https://www.$DOMAIN"

[Install]
WantedBy=multi-user.target
SERVICE_CONFIG

systemctl daemon-reload
systemctl enable securechat-backend.service
systemctl start securechat-backend.service

echo ""
echo -e "${GREEN}========================================"
echo "✅ HTTPS/WSS Setup Complete!"
echo "========================================${NC}"
echo ""
echo "Your application is now running securely:"
echo ""
echo -e "  🌐 Frontend: ${GREEN}https://$DOMAIN${NC}"
echo -e "  🔌 API: ${GREEN}https://$DOMAIN/api${NC}"
echo -e "  📡 WebSocket: ${GREEN}wss://$DOMAIN/ws${NC}"
echo ""
echo "Backend Status:"
systemctl status securechat-backend.service --no-pager
echo ""
echo "Nginx Status:"
systemctl status nginx --no-pager
echo ""
echo -e "${YELLOW}Important Next Steps:${NC}"
echo "1. Update frontend environment variable:"
echo "   VITE_API_URL=https://$DOMAIN"
echo ""
echo "2. Build and deploy frontend:"
echo "   cd $APP_DIR/frontend"
echo "   npm install"
echo "   npm run build"
echo "   sudo cp -r dist/* /var/www/securechat/"
echo ""
echo "3. View logs:"
echo "   journalctl -u securechat-backend.service -f"
echo ""
echo "4. SSL certificate will auto-renew (verify with):"
echo "   certbot renew --dry-run"
echo ""
echo "5. Monitor certificate expiration:"
echo "   certbot certificates"
echo ""
