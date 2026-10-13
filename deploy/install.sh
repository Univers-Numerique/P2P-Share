#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  P2P Share — installation / mise à jour sur un VPS
#  Ubuntu 22.04+ ou Debian 12+, exécuté en root.
#
#  Première installation :
#    curl -fsSL https://raw.githubusercontent.com/Univers-Numerique/P2P-Share/main/deploy/install.sh \
#      | sudo bash -s -- --email vous@exemple.com
#
#  Mise à jour : relancer exactement la même commande (le script est idempotent).
#
#  Options :
#    --email EMAIL      Adresse pour Let's Encrypt (obligatoire à la 1re installation)
#    --domain DOMAINE   Défaut : p2p.nexusnumerique.com
#    --branch BRANCHE   Défaut : main
#    --turn             Installe aussi un serveur TURN (coturn) : connexions directes
#                       plus fiables derrière les NAT stricts
#    --no-firewall      Ne touche pas au pare-feu (ufw)
#    --skip-dns-check   N'échoue pas si le DNS ne pointe pas encore vers ce serveur
#    --staging          Certificat de test Let's Encrypt (pour essayer sans quota)
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

DOMAIN="p2p.nexusnumerique.com"
REPO="https://github.com/Univers-Numerique/P2P-Share.git"
BRANCH="main"
EMAIL=""
ENABLE_TURN=0
FIREWALL=1
DNS_CHECK=1
STAGING=0

APP_USER="p2pshare"
APP_DIR="/opt/p2pshare"
ENV_DIR="/etc/p2pshare"
ENV_FILE="$ENV_DIR/p2pshare.env"
PORT=3000
NODE_MAJOR=22
WEBROOT="/var/www/certbot"
TURN_PORT=3478
TURN_MIN_PORT=49160
TURN_MAX_PORT=49200

# ── Helpers ───────────────────────────────────────────────────────
info() { printf '\033[1;36m▶ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✔ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m⚠ %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m✖ %s\033[0m\n' "$*" >&2; exit 1; }

# Sets KEY=VALUE in the env file, keeping any other (manual) settings
set_env() {
  local key="$1" value="$2"
  touch "$ENV_FILE"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

get_env() {
  [[ -f "$ENV_FILE" ]] && grep -E "^$1=" "$ENV_FILE" | head -n1 | cut -d= -f2- || true
}

# ── Arguments ─────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --email)          EMAIL="${2:?--email attend une valeur}"; shift 2 ;;
    --domain)         DOMAIN="${2:?--domain attend une valeur}"; shift 2 ;;
    --branch)         BRANCH="${2:?--branch attend une valeur}"; shift 2 ;;
    --turn)           ENABLE_TURN=1; shift ;;
    --no-firewall)    FIREWALL=0; shift ;;
    --skip-dns-check) DNS_CHECK=0; shift ;;
    --staging)        STAGING=1; shift ;;
    -h|--help)        sed -n '2,23p' "$0" 2>/dev/null || true; exit 0 ;;
    *)                die "Option inconnue : $1 (voir --help)" ;;
  esac
done

CERT_DIR="/etc/letsencrypt/live/$DOMAIN"

# ── Pré-requis ────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Lancez ce script en root (sudo)."
command -v apt-get >/dev/null || die "Seuls Debian et Ubuntu sont pris en charge."
if [[ ! -f "$CERT_DIR/fullchain.pem" && -z "$EMAIL" ]]; then
  die "Première installation : indiquez une adresse pour Let's Encrypt avec --email vous@exemple.com"
fi

info "Installation des paquets système"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git gnupg nginx certbot openssl ufw >/dev/null
ok "Paquets système installés"

# ── Node.js ───────────────────────────────────────────────────────
current_node=$(node -v 2>/dev/null | sed 's/^v\([0-9]*\).*/\1/' || echo 0)
if [[ "${current_node:-0}" -lt 18 ]]; then
  info "Installation de Node.js $NODE_MAJOR (NodeSource)"
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - >/dev/null
  apt-get install -y -qq nodejs >/dev/null
fi
NODE_BIN=$(command -v node)
ok "Node.js $($NODE_BIN -v)"

# ── Vérification DNS ──────────────────────────────────────────────
public_ip=$(curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
dns_ips=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')
if [[ " $dns_ips " != *" $public_ip "* ]]; then
  msg="Le domaine $DOMAIN pointe vers [${dns_ips:-aucune IP}] alors que ce serveur est $public_ip. Créez un enregistrement DNS A : $DOMAIN → $public_ip"
  [[ $DNS_CHECK -eq 1 ]] && die "$msg (ou relancez avec --skip-dns-check)"
  warn "$msg"
else
  ok "DNS : $DOMAIN → $public_ip"
fi

# ── Utilisateur système ───────────────────────────────────────────
if ! id "$APP_USER" &>/dev/null; then
  info "Création de l'utilisateur système $APP_USER"
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$APP_USER"
fi

# ── Code de l'application ─────────────────────────────────────────
# The code belongs to root: the service user can read it but never modify it.
if [[ -d "$APP_DIR/.git" ]]; then
  info "Mise à jour du code ($BRANCH)"
  git -C "$APP_DIR" fetch --quiet origin "$BRANCH"
  git -C "$APP_DIR" reset --quiet --hard "origin/$BRANCH"
else
  info "Téléchargement du code depuis $REPO"
  rm -rf "$APP_DIR"
  git clone --quiet --branch "$BRANCH" "$REPO" "$APP_DIR"
fi
chown -R root:root "$APP_DIR"
ok "Code à jour : $(git -C "$APP_DIR" log -1 --format='%h — %s')"

info "Installation des dépendances npm"
(cd "$APP_DIR" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error)
ok "Dépendances installées"

# ── Configuration ─────────────────────────────────────────────────
mkdir -p "$ENV_DIR"
set_env PORT "$PORT"
set_env HOST "127.0.0.1"
set_env TRUST_PROXY "1"
set_env NODE_ENV "production"

# ── TURN (optionnel) ──────────────────────────────────────────────
if [[ $ENABLE_TURN -eq 1 ]]; then
  info "Installation du serveur TURN (coturn)"
  apt-get install -y -qq coturn >/dev/null
  turn_secret=$(get_env TURN_SECRET)
  [[ -n "$turn_secret" ]] || turn_secret=$(openssl rand -hex 32)

  # Cloud providers (AWS, GCP…) put the public IP behind NAT: tell coturn about it
  private_ip=$(hostname -I | awk '{print $1}')
  external_ip_line=""
  if [[ -n "$public_ip" && "$public_ip" != "$private_ip" ]]; then
    external_ip_line="external-ip=${public_ip}/${private_ip}"
  fi

  cat > /etc/turnserver.conf <<EOF
# Généré par P2P Share deploy/install.sh
listening-port=$TURN_PORT
min-port=$TURN_MIN_PORT
max-port=$TURN_MAX_PORT
fingerprint
use-auth-secret
static-auth-secret=$turn_secret
realm=$DOMAIN
server-name=$DOMAIN
$external_ip_line
no-cli
no-multicast-peers
# WebRTC already encrypts the media (DTLS): plain TURN on 3478 is enough
no-tls
no-dtls
simple-log
syslog
# Interdit de relayer vers des réseaux privés (protection du réseau interne du VPS)
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=::1
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
EOF
  chmod 640 /etc/turnserver.conf
  chown root:turnserver /etc/turnserver.conf 2>/dev/null || true
  [[ -f /etc/default/coturn ]] && sed -i 's/^#\?TURNSERVER_ENABLED=.*/TURNSERVER_ENABLED=1/' /etc/default/coturn
  systemctl enable --quiet coturn
  systemctl restart coturn

  set_env TURN_URLS "turn:$DOMAIN:$TURN_PORT?transport=udp,turn:$DOMAIN:$TURN_PORT?transport=tcp"
  set_env TURN_SECRET "$turn_secret"
  ok "TURN actif sur le port $TURN_PORT"
fi

chown root:"$APP_USER" "$ENV_FILE"
chmod 640 "$ENV_FILE"

# ── Service systemd ───────────────────────────────────────────────
info "Configuration du service systemd"
cat > /etc/systemd/system/p2pshare.service <<EOF
[Unit]
Description=P2P Share — partage de fichiers P2P chiffré
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$NODE_BIN server.js
Restart=always
RestartSec=3
LimitNOFILE=65536

# Durcissement
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --quiet p2pshare
systemctl restart p2pshare

for _ in $(seq 1 20); do
  curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" && break
  sleep 0.5
done
curl -fsS -o /dev/null "http://127.0.0.1:$PORT/" || die "Le service ne répond pas. Logs : journalctl -u p2pshare -n 50"
ok "Service p2pshare démarré"

# ── Pare-feu ──────────────────────────────────────────────────────
if [[ $FIREWALL -eq 1 ]]; then
  info "Configuration du pare-feu (ufw)"
  # Keep every port sshd listens on open, so this never locks you out
  ssh_ports=$(ss -Htlnp 2>/dev/null | awk '/sshd/ {n=split($4,a,":"); print a[n]}' | sort -u)
  for p in ${ssh_ports:-22}; do ufw allow "$p/tcp" >/dev/null; done
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
  if [[ $ENABLE_TURN -eq 1 ]]; then
    ufw allow "$TURN_PORT/udp" >/dev/null
    ufw allow "$TURN_PORT/tcp" >/dev/null
    ufw allow "$TURN_MIN_PORT:$TURN_MAX_PORT/udp" >/dev/null
  fi
  if ufw status | grep -q "Status: active"; then
    ok "Règles ajoutées au pare-feu existant"
  else
    # Enabling ufw would block every other public service on this VPS: only do it when there is none
    known=" ${ssh_ports:-22} 80 443 $TURN_PORT "
    others=$(ss -Htln 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|\[::1\]|::1)' \
             | awk '{n=split($0,a,":"); print a[n]}' | sort -un | while read -r p; do
               [[ "$known" == *" $p "* ]] || echo "$p"; done | tr '\n' ' ')
    if [[ -n "$others" ]]; then
      warn "Pare-feu NON activé : d'autres services écoutent publiquement (ports : $others)."
      warn "Les règles sont prêtes ; après avoir autorisé ces ports (ufw allow PORT/tcp), activez-le avec : ufw enable"
    else
      ufw --force enable >/dev/null
      ok "Pare-feu activé (SSH ${ssh_ports:-22}, 80, 443$([[ $ENABLE_TURN -eq 1 ]] && echo ", TURN"))"
    fi
  fi
fi

# ── Nginx + HTTPS ─────────────────────────────────────────────────
NGINX_SITE="/etc/nginx/sites-available/p2pshare"
mkdir -p "$WEBROOT"
rm -f /etc/nginx/sites-enabled/default

write_nginx_http_only() {
  cat > "$NGINX_SITE" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 503; }
}
EOF
}

write_nginx_full() {
  cat > "$NGINX_SITE" <<EOF
# Généré par P2P Share deploy/install.sh
map \$http_upgrade \$p2pshare_connection {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate     $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:p2pshare_ssl:10m;
    ssl_session_timeout 1d;

    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_http_version 1.1;

        # WebSockets (Socket.io + PeerJS)
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$p2pshare_connection;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        proxy_set_header Host \$host;
        # Overwritten (not appended): the app rate-limits on this IP, clients must not spoof it
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
}

if [[ ! -f "$CERT_DIR/fullchain.pem" ]]; then
  info "Obtention du certificat HTTPS Let's Encrypt"
  write_nginx_http_only
  ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/p2pshare
  nginx -t -q && systemctl reload-or-restart nginx
  certbot_args=(certonly --webroot -w "$WEBROOT" -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive
                --keep-until-expiring --deploy-hook "systemctl reload nginx")
  [[ $STAGING -eq 1 ]] && certbot_args+=(--staging)
  certbot "${certbot_args[@]}" || die "Échec Let's Encrypt. Vérifiez le DNS et que le port 80 est joignable depuis Internet."
fi
ok "Certificat présent ($CERT_DIR)"

write_nginx_full
ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/p2pshare
nginx -t -q || die "Configuration nginx invalide (nginx -t)"
systemctl enable --quiet nginx
systemctl reload-or-restart nginx
systemctl enable --quiet certbot.timer 2>/dev/null || true
ok "Nginx configuré (renouvellement automatique du certificat actif)"

# ── Vérification finale ───────────────────────────────────────────
if curl -fsS -o /dev/null --max-time 15 "https://$DOMAIN/" 2>/dev/null; then
  ok "https://$DOMAIN répond"
else
  warn "https://$DOMAIN ne répond pas encore depuis ce serveur (DNS en propagation ?). Vérifiez depuis votre navigateur."
fi

cat <<EOF

════════════════════════════════════════════════════════════
  P2P Share est en ligne : https://$DOMAIN
════════════════════════════════════════════════════════════
  Logs           journalctl -u p2pshare -f
  Redémarrer     systemctl restart p2pshare
  Configuration  $ENV_FILE
  Mettre à jour  relancer ce script
EOF
