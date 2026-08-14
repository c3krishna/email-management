#!/bin/bash
# ============================================================
# Email Management Dashboard — Full Deployment Script
# Server: app server (82.113.92.114) or a dedicated VM
# Domain: email-management.worktual.tech
# ============================================================

set -e
echo "🚀 Deploying Email Management Dashboard..."

# ---- Config ----
APP_DIR="/var/www/email-management"
LOG_DIR="/var/log/email-mgmt"
DOMAIN="email-management.worktual.tech"
NODE_VER="20"

# ---- 1. System deps ----
echo "[1/8] Installing system dependencies..."
apt-get update -qq
apt-get install -y nodejs npm nginx certbot python3-certbot-nginx

# ---- 2. Create directories ----
echo "[2/8] Creating directories..."
mkdir -p "$APP_DIR/backend" "$APP_DIR/frontend" "$LOG_DIR"

# ---- 3. Copy source ----
echo "[3/8] Deploying source files..."
# Run from the repo root or adjust paths
cp -r ./backend/* "$APP_DIR/backend/"
cp -r ./frontend/* "$APP_DIR/frontend/"
cp ecosystem.config.js "$APP_DIR/"

# ---- 4. Backend setup ----
echo "[4/8] Installing backend dependencies..."
cd "$APP_DIR/backend"

# Create .env if it doesn't exist
if [ ! -f .env ]; then
  echo "⚠️  Creating .env — EDIT THIS FILE before starting!"
  cat > .env << 'ENVEOF'
DB_HOST=10.180.0.201
DB_PORT=3306
DB_USER=email_mgmt_user
DB_PASSWORD=CHANGE_ME_STRONG_PASSWORD
DB_NAME=worktual_email_campaign

PORT=5200
NODE_ENV=production
FRONTEND_URL=https://email-management.worktual.tech

NOTIFY_SMTP_HOST=localhost
NOTIFY_SMTP_PORT=25
NOTIFY_FROM=noreply@worktual.tech
NOTIFY_TEAM_DEVOPS=devops-team@worktual.tech
NOTIFY_TEAM_BACKEND=backend-team@worktual.tech
NOTIFY_TEAM_EMAIL=email-team@worktual.tech

ALERT_FAILED_THRESHOLD=50
ALERT_BOUNCE_THRESHOLD=20
ALERT_SPAM_THRESHOLD=10
ENVEOF
  echo "📝 Edit $APP_DIR/backend/.env with your DB credentials!"
fi

npm install --omit=dev

# ---- 5. Frontend build ----
echo "[5/8] Building frontend..."
cd "$APP_DIR/frontend"
npm install
VITE_API_URL=/api npm run build

# ---- 6. PM2 setup ----
echo "[6/8] Setting up PM2..."
npm install -g pm2 2>/dev/null || true
cd "$APP_DIR"
pm2 stop email-mgmt-api 2>/dev/null || true
pm2 start ecosystem.config.js
pm2 save

# ---- 7. Nginx setup ----
echo "[7/8] Configuring Nginx..."
cp /path/to/nginx.conf "/etc/nginx/sites-available/email-management"
ln -sf "/etc/nginx/sites-available/email-management" "/etc/nginx/sites-enabled/"
nginx -t && systemctl reload nginx

# ---- 8. SSL (Let's Encrypt) ----
echo "[8/8] Setting up SSL..."
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@worktual.tech || echo "⚠️  SSL setup skipped — run manually: certbot --nginx -d $DOMAIN"

# ---- Create MariaDB user (if needed) ----
echo ""
echo "=============================================="
echo "📊 Create DB read-only user (run on DB server):"
echo "=============================================="
cat << 'SQLEOF'
-- Run on 10.180.0.201 (MariaDB):
CREATE USER IF NOT EXISTS 'email_mgmt_user'@'%' IDENTIFIED BY 'CHANGE_ME_STRONG_PASSWORD';
GRANT SELECT ON worktual_email_campaign.email_delivery_details TO 'email_mgmt_user'@'%';
FLUSH PRIVILEGES;
SQLEOF

echo ""
echo "✅ Deployment complete!"
echo "📧 Dashboard: https://$DOMAIN"
echo "🔌 API: https://$DOMAIN/api/health"
echo ""
echo "⚠️  Remember to:"
echo "  1. Edit $APP_DIR/backend/.env with real credentials"
echo "  2. Create the MariaDB user above"
echo "  3. Set PM2 to start on boot: pm2 startup"
echo "  4. Point DNS A record: $DOMAIN → $(curl -s ifconfig.me)"
