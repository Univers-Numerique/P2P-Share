#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  P2P Share — mise à jour de la version en production
#  À lancer en root sur le VPS, après une installation faite avec install.sh.
#
#    sudo p2pshare-update              (raccourci créé à la première exécution)
#
#  Première fois, ou si le raccourci n'existe pas encore :
#    curl -fsSL https://raw.githubusercontent.com/Univers-Numerique/P2P-Share/main/deploy/update.sh | sudo bash
#
#  Ce que fait le script :
#    1. récupère la dernière version sur GitHub et liste ce qui change ;
#    2. refuse de continuer si des salons sont ouverts (sauf --yes) : un redémarrage les ferme ;
#    3. installe le code, les dépendances si elles ont changé, puis redémarre le service ;
#    4. vérifie que le service répond ; sinon revient tout seul à la version précédente.
#
#  Options :
#    --check        Affiche ce qui serait mis à jour, sans rien changer
#    --yes, -y      Met à jour même si des salons sont ouverts (ils seront fermés)
#    --rollback     Revient à la version d'avant la dernière mise à jour
#    --force        Réinstalle et redémarre même si le code est déjà à jour
#    --branch NOM   Autre branche que celle installée (défaut : la branche courante)
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/p2pshare}"
SERVICE="${SERVICE:-p2pshare}"
ENV_FILE="${ENV_FILE:-/etc/p2pshare/p2pshare.env}"
STATE_DIR="${STATE_DIR:-/var/lib/p2pshare}"
SHORTCUT="${SHORTCUT:-/usr/local/bin/p2pshare-update}"
PREVIOUS_FILE="$STATE_DIR/previous-commit"

MODE="update"
ASSUME_YES=0
FORCE=0
BRANCH=""

# ── Helpers ───────────────────────────────────────────────────────
info() { printf '\033[1;36m▶ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✔ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m⚠ %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m✖ %s\033[0m\n' "$*" >&2; exit 1; }

app_git() { git -C "$APP_DIR" "$@"; }
short()   { app_git rev-parse --short "$1"; }

app_port() {
  local port=""
  [[ -f "$ENV_FILE" ]] && port=$(grep -E '^PORT=' "$ENV_FILE" | head -n1 | cut -d= -f2- || true)
  echo "${port:-3000}"
}

is_healthy() {
  curl -fsS -m 5 -o /dev/null "http://127.0.0.1:$(app_port)/"
}

wait_healthy() {
  for _ in $(seq 1 40); do
    is_healthy 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}

# Prints the number of open salons, or nothing when the running version has no /healthz yet
active_salons() {
  local body
  body=$(curl -fsS -m 5 "http://127.0.0.1:$(app_port)/healthz" 2>/dev/null) || return 0
  echo "$body" | sed -n 's/.*"salons":\([0-9][0-9]*\).*/\1/p'
}

# Puts the given commit in place and restarts. Returns non-zero if the service does not come back.
# (Each step is checked explicitly: `set -e` is ignored inside a function called from an `if`.)
deploy_commit() {
  local target="$1" from="$2"
  app_git reset --quiet --hard "$target" || return 1
  if [[ ! -d "$APP_DIR/node_modules" ]] || ! app_git diff --quiet "$from" "$target" -- package-lock.json package.json; then
    info "Dépendances modifiées : installation"
    (cd "$APP_DIR" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error) || return 1
  fi
  systemctl restart "$SERVICE" || return 1
  wait_healthy || return 1
}

install_shortcut() {
  [[ -f "$SHORTCUT" ]] && return 0
  printf '#!/bin/sh\nexec bash %s/deploy/update.sh "$@"\n' "$APP_DIR" > "$SHORTCUT" 2>/dev/null && chmod +x "$SHORTCUT" \
    && ok "Raccourci créé : la prochaine fois, lancez simplement « sudo p2pshare-update »" || true
}

# ── Arguments ─────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)    MODE="check"; shift ;;
    --rollback) MODE="rollback"; shift ;;
    --yes|-y)   ASSUME_YES=1; shift ;;
    --force)    FORCE=1; shift ;;
    --branch)   BRANCH="${2:?--branch attend une valeur}"; shift 2 ;;
    -h|--help)  sed -n '2,23p' "$0" 2>/dev/null || true; exit 0 ;;
    *)          die "Option inconnue : $1 (voir --help)" ;;
  esac
done

# ── Pré-requis ────────────────────────────────────────────────────
[[ $EUID -eq 0 || "${ALLOW_NON_ROOT:-0}" == "1" ]] || die "Lancez ce script en root (sudo)."
[[ -d "$APP_DIR/.git" ]] || die "P2P Share n'est pas installé dans $APP_DIR. Faites d'abord l'installation avec deploy/install.sh."
for cmd in git curl npm systemctl; do
  command -v "$cmd" >/dev/null || die "Commande manquante : $cmd"
done

CURRENT=$(app_git rev-parse HEAD)
[[ -n "$BRANCH" ]] || BRANCH=$(app_git rev-parse --abbrev-ref HEAD)
[[ "$BRANCH" != "HEAD" ]] || BRANCH="main"

# Refuses to close live salons unless --yes was given (no prompt: the script is often piped from curl)
confirm_salons() {
  local count
  count=$(active_salons)
  [[ -n "$count" && "$count" -gt 0 ]] || return 0
  [[ $ASSUME_YES -eq 1 ]] && { warn "$count salon(s) ouvert(s) : ils vont être fermés."; return 0; }
  die "$count salon(s) ouvert(s) en ce moment : le redémarrage les fermerait et couperait les transferts en cours. Réessayez plus tard, ou forcez avec --yes."
}

# ── Rollback ──────────────────────────────────────────────────────
if [[ "$MODE" == "rollback" ]]; then
  [[ -f "$PREVIOUS_FILE" ]] || die "Aucune version précédente enregistrée (pas encore de mise à jour faite avec ce script)."
  TARGET=$(cat "$PREVIOUS_FILE")
  app_git cat-file -e "$TARGET^{commit}" 2>/dev/null || die "La version précédente ($TARGET) est introuvable dans le dépôt."
  [[ "$TARGET" != "$CURRENT" ]] || die "La version précédente est déjà celle en service."
  info "Retour à la version précédente : $(short "$CURRENT") → $(short "$TARGET") ($(app_git log -1 --format=%s "$TARGET"))"
  confirm_salons
  if deploy_commit "$TARGET" "$CURRENT"; then
    echo "$CURRENT" > "$PREVIOUS_FILE"
    ok "Version $(short "$TARGET") en service. La prochaine mise à jour réinstallera la dernière version."
    exit 0
  fi
  die "Le service ne répond pas après le retour arrière. Logs : journalctl -u $SERVICE -n 50"
fi

# ── Recherche de mise à jour ──────────────────────────────────────
info "Recherche d'une mise à jour (branche $BRANCH)"
app_git fetch --quiet origin "$BRANCH" || die "Impossible de joindre GitHub."
TARGET=$(app_git rev-parse FETCH_HEAD)

if [[ "$TARGET" == "$CURRENT" && $FORCE -eq 0 ]]; then
  ok "Déjà à jour : $(short "$CURRENT") — $(app_git log -1 --format=%s "$CURRENT")"
  install_shortcut
  exit 0
fi

if [[ "$TARGET" == "$CURRENT" ]]; then
  info "Réinstallation forcée de $(short "$CURRENT")"
elif app_git merge-base --is-ancestor "$CURRENT" "$TARGET"; then
  echo "Changements à installer ($(short "$CURRENT") → $(short "$TARGET")) :"
  app_git log --format='  • %s (%ad)' --date=short "$CURRENT..$TARGET"
else
  warn "L'historique de la branche a été réécrit : passage direct de $(short "$CURRENT") à $(short "$TARGET")."
fi

if [[ "$MODE" == "check" ]]; then
  salons=$(active_salons)
  [[ -n "$salons" ]] && echo "Salons ouverts en ce moment : $salons"
  echo "Rien n'a été modifié (--check)."
  exit 0
fi

confirm_salons

# ── Mise à jour ───────────────────────────────────────────────────
mkdir -p "$STATE_DIR"
info "Installation de $(short "$TARGET")"
if deploy_commit "$TARGET" "$CURRENT"; then
  [[ "$TARGET" != "$CURRENT" ]] && echo "$CURRENT" > "$PREVIOUS_FILE"
  ok "Service redémarré et opérationnel"
else
  warn "La nouvelle version ne démarre pas : retour automatique à $(short "$CURRENT")"
  journalctl -u "$SERVICE" -n 15 --no-pager 2>/dev/null || true
  if deploy_commit "$CURRENT" "$TARGET"; then
    die "Mise à jour annulée. L'ancienne version $(short "$CURRENT") est de nouveau en service."
  fi
  die "Échec de la mise à jour ET du retour arrière. Intervention manuelle nécessaire : journalctl -u $SERVICE -n 50"
fi

# The system setup (nginx, systemd unit, firewall, TURN) is only applied by install.sh
if [[ "$TARGET" != "$CURRENT" ]] && ! app_git diff --quiet "$CURRENT" "$TARGET" -- deploy/install.sh; then
  warn "Le script d'installation a changé. Pour appliquer aussi les changements de configuration système (nginx, service, pare-feu), relancez deploy/install.sh avec vos options habituelles."
fi

install_shortcut

cat <<EOF

════════════════════════════════════════════════════════════
  P2P Share est à jour : $(short "$TARGET") — $(app_git log -1 --format=%s "$TARGET")
════════════════════════════════════════════════════════════
  Les visiteurs récupèrent la nouvelle version en rechargeant la page.
  Revenir en arrière   sudo p2pshare-update --rollback
  Logs                 journalctl -u $SERVICE -f
EOF
