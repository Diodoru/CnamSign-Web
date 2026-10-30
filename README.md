# CnamSign Web

Interface web multi-utilisateurs pour automatiser et suivre l'émargement sur
**CnamSignE** (Le Cnam), construite autour du projet
[ndh51/CnamSign](https://github.com/ndh51/CnamSign).

- FastAPI + Jinja2 + HTMX + Tailwind (CDN), SQLAlchemy/SQLite, APScheduler
- Un seul conteneur pour tous les utilisateurs
- Identifiants Le Cnam chiffrés au repos (Fernet), déchiffrés en mémoire uniquement pendant une vérification
- 100 % automatique : l'utilisateur enregistre ses identifiants + PIN et active « Signature auto »
- Notifications par e-mail (réussite / échec) envoyées à l'adresse Le Cnam de l'utilisateur, et Discord (webhook) en option
- Historique avec la matière / le cours extrait du mail d'émargement

## Fonctionnement

### Ce que fait le projet upstream

CnamSign pilote un **Chromium headless (Playwright)** :

1. `mail_watcher.MailWatcher` se connecte à **Outlook Web** (SSO Microsoft → Shibboleth `idp.lecnam.net`),
   ouvre le dossier `Emargements` et extrait le dernier **code de session à 6 chiffres** reçu par e-mail ;
2. `signer.CnamSigner.sign(code)` ouvre `cnamsigne.lecnam.net`, gère le SSO, saisit le **code PIN**
   sur le clavier virtuel (lecture des touches par nom d'image, puis OCR Tesseract en secours),
   saisit le code de session, coche « Je confirme ma présence » et signe avec la **signature enregistrée**.

Le code upstream lit les identifiants dans des variables globales (`config.py`, chargé à l'import) et
travaille avec des chemins relatifs (`browser_profile/`, `screenshots/`, `processed_codes.txt`).

### Comment l'application le réutilise

`app/services/cnam_service.py` (`CnamService`) lance le code upstream dans un **sous-processus
par opération** (`app/services/cnam_worker.py`) :

| Contrainte upstream | Solution |
|---|---|
| Une seule identité par processus (`config` global) | identifiants injectés dans l'environnement du sous-processus avant l'import de `config` |
| Chemins relatifs | `cwd` = `DATA_DIR/users/<id>/` → profil navigateur, captures et codes traités isolés par utilisateur |
| Watchdog `SIGALRM` (thread principal uniquement) | le worker est le thread principal de son propre processus |
| Chromium peut bloquer | timeout + kill du groupe de processus |

Les secrets passent par un **pipe stdin** (ni argument de ligne de commande, ni fichier), et les
variables `SECRET_*`/`SMTP_*` du serveur ne sont pas transmises au worker.

### Cycle d'un code d'émargement

1. Le planificateur (toutes les minutes, `lun-sam`, `8h-19h59`) lance les utilisateurs dont l'intervalle est écoulé.
2. Code trouvé par e-mail et signature réussie → **SUCCESS** (+ e-mail si l'option est cochée).
3. Échec → statut « Nouvelle tentative », le code est retenté au cycle suivant (sans log ni e-mail).
4. Après `MAX_SIGN_RETRIES` échecs → **FAILED** (+ e-mail d'alerte si l'option est cochée), le code est abandonné.

Aucune saisie manuelle n'est nécessaire ; le bouton « Vérifier maintenant » force simplement un cycle.

## Notifications e-mail

Les e-mails (texte + HTML) partent vers l'adresse Le Cnam enregistrée par l'utilisateur.

- **Relais global (recommandé)** : `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
  `SMTP_FROM_EMAIL`, `SMTP_USE_TLS` dans `.env`. Pour Gmail, utilisez un mot de passe d'application.
- **Repli sans relais** : chaque utilisateur s'envoie le mail via `smtp.office365.com:587` avec son propre
  compte Le Cnam. Microsoft retire progressivement l'authentification SMTP par mot de passe et les
  établissements la désactivent souvent : si l'e-mail de test du dashboard échoue, configurez un relais global.

L'e-mail indique la **matière / le cours**, extrait du mail d'émargement par l'upstream
(`MailWatcher.extract_subject`). Quand l'upstream ne le trouve pas, « Non spécifiée » est affiché.

## Notifications Discord (optionnel, par utilisateur)

Dans la carte Notifications : URL du webhook (Paramètres du salon › Intégrations › Webhooks), ID utilisateur
Discord et nom de l'étudiant (sinon déduit de l'e-mail), puis cocher les événements voulus :

| Événement | Message | Options |
|---|---|---|
| Signature réussie | embed Élève / Matière / Code / Heure (présentation de l'upstream) | envoi, mention `@moi` |
| Échec définitif | embed d'alerte + détail de l'erreur | envoi, mention `@moi` |

La mention `<@ID>` n'est ajoutée que si la case « Inclure la mention » de l'événement est cochée
(elle nécessite l'ID utilisateur Discord). Les autres mentions (`@everyone`, `@here`) sont toujours bloquées.

L'URL du webhook est chiffrée en base (elle suffit pour poster dans le salon). Les variables
`DISCORD_WEBHOOK_URL`, `DISCORD_USER_ID` et `STUDENT_NAME` de l'upstream ne sont pas utilisées par
l'application (configuration mono-utilisateur) et ne sont jamais transmises au worker.

## Prérequis côté Le Cnam (comme pour l'upstream)

- Dans Outlook Web : un dossier `Emargements` + une règle qui y range les mails contenant « émarger » ou « code de session ».
- Sur CnamSignE : avoir enregistré sa **signature manuscrite** (menu utilisateur → *Signature enregistrée*).
- Connaître son **code PIN** CnamSignE.

> Si votre compte Microsoft exige une authentification multifacteur (MFA), la lecture d'Outlook en headless échouera :
> c'est une limite du projet upstream.

## Générer les clés

Clé de chiffrement Fernet (identifiants CNAM) :

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Clé de session (cookies signés) :

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

**Sauvegardez la clé Fernet** : si elle est perdue, les identifiants enregistrés deviennent illisibles
(chaque utilisateur devra les ressaisir). Pour une rotation, mettez `nouvelle_cle,ancienne_cle` :
la première chiffre, toutes déchiffrent.

## Développement local

```bash
git clone https://github.com/ndh51/CnamSign.git vendor/CnamSign
python -m venv .venv
.venv/Scripts/activate          # Windows (Linux/macOS : source .venv/bin/activate)
pip install -r requirements.txt -r vendor/CnamSign/requirements.txt
python -m playwright install chromium
cp .env.example .env            # puis renseigner SECRET_KEY et SECRET_ENCRYPTION_KEY
uvicorn app.main:app --reload
```

Ouvrir http://localhost:8000 : **le premier compte créé est administrateur**.
Tesseract est optionnel en local (utilisé seulement si les touches du clavier PIN ne sont pas reconnues par leur nom).
Mettre `HEADLESS=false` dans `.env` pour voir le navigateur.

## Déploiement Docker

```bash
mkdir -p secrets
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > secrets/encryption_key
python -c "import secrets; print(secrets.token_urlsafe(48))" > secrets/secret_key
chmod 600 secrets/*            # le conteneur tourne en uid 1000 : le fichier doit lui être lisible
cp .env.example .env
docker compose up -d --build
```

- Données persistantes : volume `cnamsign-data` (base SQLite + profils navigateur).
- Clés : `./secrets/` sur l'hôte, montées en lecture seule dans `/run/secrets/`.
- Un seul worker uvicorn (le planificateur tourne dans le processus) : ne pas augmenter `--workers`.
- Derrière un reverse proxy HTTPS : `SESSION_COOKIE_SECURE=true` et `APP_BASE_URL=https://...`.
- RAM : prévoir ~400 Mo par Chromium actif. `MAX_CONCURRENT_JOBS=1` sérialise les vérifications ;
  avec un intervalle de 5 min et ~45 s par vérification, comptez une dizaine d'utilisateurs par job simultané.

### Mettre à jour le code CnamSign upstream

```bash
docker compose build --build-arg CNAMSIGN_CACHEBUST=$(date +%s) && docker compose up -d
```

Pour figer une version : `CNAMSIGN_REF=<sha ou tag>` dans `.env`. Le commit utilisé est écrit dans
`/opt/cnamsign/REVISION` dans l'image.

## Sécurité

- Mots de passe de l'application : Argon2id.
- Identifiants Le Cnam, PIN et URL de webhook Discord : chiffrés avec Fernet (AES-CBC + HMAC-SHA256).
- Sessions : cookie signé `HttpOnly`, `SameSite=Lax` ; jeton CSRF sur toutes les requêtes POST.
- Limitation des tentatives de connexion (10 échecs / 15 min / IP).
- Le profil navigateur de chaque utilisateur (cookies SSO) est stocké sur disque dans le volume ; il est effacé
  quand l'utilisateur change ou supprime ses identifiants.
- Les captures d'écran de l'upstream sont purgées après `SCREENSHOT_RETENTION_DAYS` jours.

## API JSON

Authentifiée par la session web :

- `GET /api/status` : état de la dernière vérification
- `GET /api/logs?status=SUCCESS&days=7&page=1` : historique
