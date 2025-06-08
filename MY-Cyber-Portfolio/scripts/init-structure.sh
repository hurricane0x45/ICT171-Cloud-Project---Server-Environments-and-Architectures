#!/bin/bash

# Root folder
mkdir -p MY-Cyber-Portfolio && cd MY-Cyber-Portfolio

# Docker Compose file
touch docker-compose.yml

# NGINX config and SSL
mkdir -p nginx/ssl
touch nginx/public.conf

# Certbot webroot for challenges
mkdir -p certbot/www

# App: public site and internal files
mkdir -p app/public/css
mkdir -p app/public/assets
touch app/public/index.html
touch app/public/css/index.css

mkdir -p app/private/js
mkdir -p app/private/tools
mkdir -p app/private/assets
touch app/private/js/index.js
touch app/private/js/particles.js
touch app/private/js/app.js

# Scripts and README
mkdir -p scripts
touch README.md

echo "Directory tree for MY-Cyber-Portfolio created."

# Move this script inside scripts dir

mv init-structure.sh MY-Cyber-Portfolio/scripts/

echo "Successfully moved init-structure.sh to the scrips directory."
