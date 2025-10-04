# littleblog

Un blog simple qui n'utilise qu'un seul binaire pour fonctionner.

## Fonctionnalités

- Infinity scroll sur la liste des articles
- Articles avec contenu Markdown
- Recherche en temps réel
- Administration des articles
- Upload d'images

## TODO

- Catégorie

## Composants

- Backend
  - Language Go
  - Gin Web Framework
  - Accès à la base de données avec GORM
  - Base de données Sqlite3
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

    make build

