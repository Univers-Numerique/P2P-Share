# P2P Share

Application web de partage de fichiers **éphémère**, **chiffrée de bout en bout** et **P2P** (navigateur à navigateur), sans inscription ni stockage serveur.

---

## Stack technique

| Composant | Technologie |
|---|---|
| Backend (signalisation + relais) | Node.js + Express + **Socket.io** |
| Signalisation WebRTC | Serveur **PeerJS** auto-hébergé (`/peerjs`) |
| Transfert P2P | **PeerJS** (WebRTC DataChannel) |
| Chiffrement | Web Crypto API — AES-256-GCM, clés dérivées par HKDF |
| Interface | HTML/CSS/JS vanilla + polices Google |
| QR Code | qrcodejs |
| Archive ZIP | JSZip |
| PWA | manifest.json + Service Worker |

Toutes les bibliothèques client sont servies par le serveur depuis `node_modules` (aucun CDN).

---

## Installation & lancement

### Prérequis
- **Node.js** v18+

### 1. Installer

```bash
cd p2pshare
npm install
```

### 2. Lancer le serveur

```bash
npm start
```

Le serveur démarre sur **http://localhost:3000**.

### 3. Tester localement

Ouvrez **deux onglets** sur `http://localhost:3000`.

Dans le premier : cliquez **« Créer un salon »**, puis copiez le lien d'invitation.
Dans le second : collez le lien dans le champ et cliquez **« Rejoindre »** (ou ouvrez directement le lien).

> **HTTPS obligatoire hors localhost.** Le chiffrement (Web Crypto) n'est disponible que dans un contexte sécurisé : `https://` ou `http://localhost`. Pour tester depuis un autre appareil du réseau local, lancez le serveur en HTTPS, par exemple avec un certificat [mkcert](https://github.com/FiloSottile/mkcert) :
>
> ```bash
> mkcert -install && mkcert 192.168.1.20 localhost
> SSL_KEY=./192.168.1.20+1-key.pem SSL_CERT=./192.168.1.20+1.pem npm start
> ```

---

## Déploiement sur un VPS (p2p.nexusnumerique.com)

Le script [deploy/install.sh](deploy/install.sh) installe tout sur un serveur **Ubuntu 22.04+ ou Debian 12+** :
Node.js, l'application dans un service systemd durci, Nginx en reverse proxy (WebSockets compris), le certificat HTTPS Let's Encrypt avec renouvellement automatique, le pare-feu, et en option un serveur TURN.

### 1. DNS

Créez un enregistrement **A** `p2p.nexusnumerique.com` → adresse IP du VPS. Le script vérifie qu'il est en place avant de demander le certificat.

### 2. Installation

Connecté au VPS en SSH :

```bash
curl -fsSL https://raw.githubusercontent.com/Univers-Numerique/P2P-Share/main/deploy/install.sh \
  | sudo bash -s -- --email vous@nexusnumerique.com
```

Ajoutez `--turn` pour installer aussi un serveur TURN (coturn) : les connexions directes passent alors même derrière les NAT stricts (4G, réseaux d'entreprise) au lieu d'utiliser le relais Socket.io.

| Option | Effet |
|---|---|
| `--email EMAIL` | Adresse pour Let's Encrypt (obligatoire la première fois) |
| `--turn` | Installe et configure coturn (identifiants temporaires, ports 3478 et 49160-49200/udp) |
| `--domain DOMAINE` | Autre domaine que `p2p.nexusnumerique.com` |
| `--branch BRANCHE` | Autre branche Git que `main` |
| `--no-firewall` | Ne modifie pas le pare-feu |
| `--skip-dns-check` | Continue même si le DNS ne pointe pas encore vers le serveur |
| `--staging` | Certificat de test Let's Encrypt |

> **Pare-feu** : si `ufw` est déjà actif, le script ajoute seulement ses règles. S'il est inactif et que d'autres services écoutent sur le VPS, il ne l'active pas et affiche les ports concernés, pour ne rien couper.

### 3. Mises à jour

Poussez sur `main`, puis relancez **la même commande** : le script récupère le code, réinstalle les dépendances et redémarre le service. La configuration et le certificat sont conservés.

### Exploitation

| | |
|---|---|
| Logs | `journalctl -u p2pshare -f` |
| Redémarrer | `systemctl restart p2pshare` |
| Configuration | `/etc/p2pshare/p2pshare.env` (puis redémarrer) |
| Code | `/opt/p2pshare` (appartient à root, le service tourne avec l'utilisateur `p2pshare` en lecture seule) |

---

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `PORT` | `3000` | Port d'écoute |
| `HOST` | `0.0.0.0` | Interface d'écoute |
| `SSL_KEY` / `SSL_CERT` | — | Chemins de la clé et du certificat pour servir directement en HTTPS |
| `TRUST_PROXY` | — | `1` derrière un reverse proxy (IP client lue dans `X-Forwarded-For`) |
| `ALLOWED_ORIGINS` | — | Origines supplémentaires autorisées pour Socket.io (séparées par des virgules). Par défaut, seule l'origine du site est acceptée |
| `RELAY_BYTES_PER_MIN` | `314572800` (300 Mo) | Débit maximal du relais par adresse IP |
| `SESSION_GRACE_MS` | `900000` (15 min) | Temps pendant lequel un membre déconnecté (téléphone verrouillé…) garde sa place |
| `TURN_URLS` | — | Serveur(s) TURN, ex. `turn:turn.exemple.com:3478` (séparés par des virgules) |
| `TURN_SECRET` | — | Secret partagé coturn (`use-auth-secret`) : chaque visiteur reçoit des identifiants valables 12 h |
| `TURN_USERNAME` / `TURN_CREDENTIAL` | — | Identifiants TURN fixes (si pas de `TURN_SECRET`) |

---

## Architecture

```
[Navigateur A] ←——— WebRTC DataChannel (chiffré) ———→ [Navigateur B]
       ↑                                                      ↑
       └————→ [Serveur Node.js : Socket.io + PeerJS] ←————————┘
               signalisation · présence · relais de secours
```

### Chiffrement de bout en bout

- À la création du salon, le navigateur de l'hôte génère une clé aléatoire de 128 bits.
- Cette clé n'existe **que dans le fragment `#` du lien d'invitation**, que les navigateurs n'envoient jamais au serveur.
- Deux sous-clés en sont dérivées (HKDF-SHA-256) :
  - une clé **AES-256-GCM** qui chiffre chaque morceau de fichier et les métadonnées (nom, taille, type) ;
  - un **jeton d'accès** : le serveur n'en garde que l'empreinte SHA-256 et refuse l'entrée à quiconque n'a pas le lien complet.
- Chaque morceau est authentifié avec son identifiant de transfert et son numéro de séquence : un morceau altéré, rejoué ou réordonné fait échouer le transfert.

Le serveur voit les pseudonymes, le nombre et la taille approximative des morceaux, mais **jamais le contenu ni le nom des fichiers**, y compris quand il sert de relais.

### Relais de secours

Si la connexion WebRTC directe échoue (NAT strict, pare-feu), les morceaux chiffrés transitent par Socket.io. Le serveur vérifie que l'expéditeur et le destinataire sont dans le même salon et applique une limite de débit. Le contrôle de flux se fait par accusés de réception de bout en bout. Dans la liste des membres, un point vert indique une connexion directe, un point orange le relais.

### Cycle de vie du salon

- Si l'hôte **quitte** le salon (bouton « Quitter »), celui-ci est détruit pour tout le monde.
- Chaque membre a une **identité stable** (identifiant + jeton de session gardés dans l'onglet). Si sa connexion se coupe (téléphone verrouillé, changement de réseau, page rechargée), il passe **« en veille »** au lieu de quitter : il garde sa place, et ses fichiers restent listés.
- À son retour, il reprend sa place automatiquement. Après une veille, ses fichiers sont toujours disponibles. Après un rechargement de la page, ils disparaissent de la liste, car le navigateur ne les a plus.
- Passé le délai de grâce (`SESSION_GRACE_MS`, 15 min par défaut), le membre est retiré ; s'il s'agit de l'hôte, le salon est fermé. Un membre qui revient après ce délai rejoint automatiquement le salon comme nouveau membre, s'il existe encore.

---

## Fonctionnalités

- Pseudonyme aléatoire modifiable (mémorisé localement)
- Création de salon, invitation par lien ou QR code
- Transfert P2P par morceaux de 64 Ko avec contrôle de flux, relais chiffré en secours
- Gros fichiers : écriture directe sur le disque (File System Access API sur Chrome/Edge). Les autres navigateurs gardent le fichier en mémoire pendant le téléchargement.
- Barres de progression à l'envoi (plusieurs destinataires) et à la réception, bouton « Réessayer »
- Aperçu intégré des images, vidéos, sons, PDF et fichiers texte/code, et bouton « Ouvrir » pour réafficher un fichier téléchargé sans nouveau transfert. Le type d'affichage dépend uniquement de l'extension : un `.html` reçu s'affiche comme du texte, jamais exécuté.
- « Ouvrir » sur un fichier téléchargé : aperçu intégré, ou menu système « Ouvrir avec… » (Web Share API) pour les autres formats (docx, zip…) sur mobile, Windows et macOS
- Scanner de QR code intégré (caméra) pour rejoindre un salon ; ouvrir un lien d'invitation fait entrer directement dans le salon
- Interface mobile : barre compacte avec panneaux « Inviter » / « Membres », cartes de fichiers adaptées, zones sûres des écrans à encoche
- Dossiers (bouton ou glisser-déposer) avec conservation de l'arborescence
- « Tout télécharger (.zip) » : récupère tous les fichiers du salon dans une archive
- Retrait automatique des fichiers d'un membre qui se déconnecte
- Reconnexion automatique après une coupure réseau
- Écran maintenu allumé pendant un envoi ou une réception (Screen Wake Lock), pour que la mise en veille automatique du téléphone ne coupe pas le transfert
- PWA installable : bouton « Installer l'application » (Chrome, Edge, Android), instructions pour iPhone/iPad, icône adaptative Android, Service Worker « réseau d'abord ». L'installation exige un certificat HTTPS reconnu par l'appareil : un certificat auto-signé ne suffit pas.
- En-têtes de sécurité (CSP, nosniff, no-referrer)

---

## Évolutions possibles

- Serveur TURN auto-hébergé (coturn) pour les réseaux très restrictifs
- Vérification visuelle de la clé entre membres (empreinte courte)
