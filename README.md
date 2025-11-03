# littleblog

Un blog simple qui n'utilise qu'un seul binaire pour fonctionner.

## Fonctionnalités

- Multiple blogs, routage par hostname
- Infinity scroll sur la liste des articles
- Articles avec contenu Markdown
- Extrait automatique pour l'index en texte brut, avec première image de l'article
- Commentaires (ajout protégé par CAPTCHA)
- Recherche en temps réel
- Administration des articles
- Upload d'images
- Menu avec différente catégories

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
  - Logs zerolog et gestion des rotations lumberjack
  - Emission vers Syslog
  - Compression gzip

- Frontend
  - Html + CSS (via template Gin)
  - Framework Alpine.js
  - N'utilise pas nodejs

## Limitations

 - Ne gère pas le chiffrage SSL, en production, il faut utiliser un reverse proxy.

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
production: false #false pour la preprod, true en production
trustedproxies:
  - 192.168.1.2 # ip du reverse proxy authorisé en entrée
trustedplatform: #cloudflare, google, flyio, ou header name exemple X-CDN-Client-IP
database:
  redis:
    addr: #localhost:6379, pour le CAPTCHA, si vide, utilisation store interne à go.
    db: 0 # le numéro du stockage redis
  db: sqlite3
  path: ./blog.db
  #db: mysql
  #dsn: mon_utilisateur:motdepasse_utilisateur@tcp(127.0.0.1:3306)/ma_base?charset=utf8mb4&parseTime=True&loc=Local
user:
  login: admin
  pass: admin1234 # mot de passe sera hashé en Argon2i au premier démarrage
staticpath: "./static"
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
    protocol: udp # "tcp", "udp", vide pour unix socket
    address: 1.2.3.4 # addresse ip du serveur syslog, vide pour unix socket
    tag: monBlogPerso
    priority: 6 # LOG_INFO
listen:
  website: 0.0.0.0:8080
blogs:
  - id: 0 # entier unique par blog, obligatoire pour la base de données
    hostname: blog.monsite.com # pour le routage en cas de multiple blog
    sitename: Mon Blog
    description: Mon blog perso
    logoimg: #logo optionnel, au format png, a mettre dans le repertoire static, exemple /static/monlogo.png
    favicon: # favicon au format png, a mettre dans le repertoire static, exemple /static/icon.png, si vide, il y a aura un icone linux
    theme: blue # blue, red, green, yellow, purple, cyan, orange, pink, gray, black, ou code couleur exemple: #000000
    menu:
    - key: "linux"
      value: "Ubuntu"
      img: "/static/linux.png"
    - key: "software"
      value: "Logiciel"
    - link: "https://github.com/clankgeek/littleblog"
      value: "GitHub"

```

