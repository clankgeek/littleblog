#!/bin/bash

# Builder l'image
docker build -t littleblog-builder .

# Créer un conteneur (sans le démarrer)
docker create --name temp-builder littleblog-builder

# Copier le binaire vers l'hôte
docker cp temp-builder:/app/build/littleblog ./build/

# Nettoyer
docker rm temp-builder