# littleblog

Un blog simple qui n'utilise qu'un seul binaire pour fonctionner.

## Fonctionnalités

- Infinity scroll sur la liste des articles
- Articles avec contenu Markdown
- Commentaires (ajout protégé par CAPTCHA)
- Recherche en temps réel
- Administration des articles
- Upload d'images
- Menu avec différente catégories

## TODO

## Composants

- Backend
  - Language Go
  - Gin Web Framework
  - CAPTCHA base64Captcha (post des commentaires)
  - Accès à la base de données avec GORM
  - Base de données Sqlite3 ou mysql
  - Middleware Session pour la page d'administration
  - Templates inclus dans le binaire
  - Configuration en Yaml (autogénéré par le binaire)
  - API RESTful (json)
  - /metrics pour Promotheus avec port dédié
  - Logs zerolog et gestion des rotations lumberjack
  - Emission vers Syslog
  - Compression gzip

- Frontend
  - Html + CSS (via template Gin)
  - Framework Alpine.js
  - N'utilise pas nodejs

## Compilation

Utilise make, gcc et golang pour compiler

### Ubuntu

Compile le binaire littleblog si vous avez un environnement golang de configuré

```bash
  make build
```

Sinon vous pouvez utiliser le builder via une image docker

```bash
  ./docker-build.sh
```

### Créer la configuration

```bash
  ./littleblog -example
```

Fichier sample `littleblog.yaml` :

```yaml
sitename: Mon Blog
description: Mon blog perso
theme: blue
trustedproxies:
  - 192.168.1.2
trustedplatform: #cloudflare, google, flyio, or header name, example X-CDN-Client-IP
database:
  redis: #localhost:6379, pour le CAPTCHA, si vide, utilisation store interne à go.
  db: sqlite3
  path: ./blog.db
  #db: mysql
  #dsn: mon_utilisateur:motdepasse_utilisateur@tcp(127.0.0.1:3306)/ma_base?charset=utf8mb4&parseTime=True&loc=Local
user:
  login: admin
  pass: admin1234 # mot de passe sera hashé en Argon2i au premier démarrage
staticpath: "./static"
production: false #false pour la preprod, true en production
logger:
  level: debug #"debug", "info", "warn", "error"
  file:
    enable: true # true pour activer le log en fichier
    path: ./littleblog.log
    maxsize: 100 #Taille max du fichier en Mo
    maxbackups: 1 #Nombre max de fichiers de backup
    maxAge: 30 #Nombre de jours avant suppression
    compress: true #Compresser les anciens logs
  syslog:
    enable: false # true pour activer l'émission vers un serveur syslog
    protocol: tcp # "tcp", "udp", vide pour unix socket
    address: 1.2.3.4 # addresse ip du serveur syslog, vide pour unix socket
    tag: monBlogPerso
    priority: 6 # LOG_INFO
listen:
  website: 0.0.0.0:8080
  metrics: 0.0.0.0:8090 #enlever pour désactiver, promotheus format
menu:
  - key: "linux"
    value: "Ubuntu"
    img: "/static/linux.png"
  - key: "software"
    value: "Logiciel"
```

### Exemple docker compose Littleblog + Promotheus + Grafana

```bash
  docker compose up
```

Dans grafana http://127.0.0.1:3000 ajouter le Data Sources Promotheus, avec la connection à http://prometheus:9090

Puis dans dashboard importer grafana.json.

