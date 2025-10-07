# littleblog

Un blog simple qui n'utilise qu'un seul binaire pour fonctionner.

## Fonctionnalités

- Infinity scroll sur la liste des articles
- Articles avec contenu Markdown
- Recherche en temps réel
- Administration des articles
- Upload d'images
- Menu avec différente catégories

## TODO

## Composants

- Backend
  - Language Go
  - Gin Web Framework
  - Accès à la base de données avec GORM
  - Base de données Sqlite3 ou mysql
  - Middleware Session pour la page d'administration
  - Templates inclus dans le binaire
  - Configuration en Yaml (autogénéré par le binaire)
  - API RESTful (json)

- Frontend
  - Html + CSS (via template Gin)
  - Framework Alpine.js
  - N'utilise pas nodejs

## Compilation

Utilise make, gcc et golang pour compiler

### Ubuntu

Compile le binaire littleblog

```bash
  make build
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
  db: sqlite3
  path: ./blog.db
  #db: mysql
  #dsn: mon_utilisateur:motdepasse_utilisateur@tcp(127.0.0.1:3306)/ma_base?charset=utf8mb4&parseTime=True&loc=Local
user:
  login: admin
  pass: admin1234
staticpath: "./static"
production: false
listen: ":8080"
menu:
  - key: "hardware"
    value: "Hardware"
    img: "/static/gpu.png"
  - key: "software"
    value: "Logiciel"
```
