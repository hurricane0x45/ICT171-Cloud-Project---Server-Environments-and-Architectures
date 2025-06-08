# MY Cyber Portfolio – ICT171 Cloud Deployment

**Student:** Alex Quartermaine  
**Student ID:** 35403093  
**Unit:** ICT171 – Introduction to Server Environments and Architectures (S1, 2025)

This subproject contains the complete Docker-based deployment of my cyber security portfolio website. It is deployed on a DigitalOcean droplet using NGINX and Certbot for SSL.


## Overview

This project demonstrates:

- A static portfolio website (HTML/CSS/JS)
- Docker containerization for modular deployment
- NGINX reverse proxy configuration
- SSL setup via Certbot
- Secure private route aliasing for internal scripts

**Live Site:** https://quartzcs.com


## Directory Structure

```
MY-Cyber-Portfolio/
├── docker-compose.yml        # Launches NGINX + Certbot
├── nginx/
│   ├── public.conf           # Public-facing NGINX configuration
│   └── ssl/                  # SSL certificates (via Certbot)
├── certbot/
│   └── www/                  # Webroot for HTTP-01 validation
├── app/
│   ├── public/               # Main static website
│   │   ├── index.html
│   │   ├── css/
│   │   │   └── index.css
│   │   └── assets/           # Logos/images
│   └── private/              # Internal JS/scripts (not exposed publicly)
│       ├── js/
│       │   ├── index.js
│       │   ├── particles.js
│       │   └── app.js
│       ├── tools/            # CLI/dev scripts
│       └── assets/           # Internal images/icons
├── scripts/                  # Additional automation tools
└── README.md                 # This file
```

## Deployment Workflow

1. Build the image:

```bash
docker build -t my-cyber-portfolio:final .
```

2. Deploy the container:

```bash
docker run -d --name quartz-nginx-final -p 80:80 -p 443:443 my-cyber-portfolio:final
```

3. SSL certificates reside in `/nginx/ssl` and are managed by Certbot.


## Technologies Used

- HTML5/CSS3/JavaScript
- NGINX
- Docker
- Certbot (Let's Encrypt)
- Ubuntu 24.10


## Template Attribution

This site is based on:

**Fimbo – Template 3**  
https://github.com/imfunniee/fimbo/tree/master/3

Modified extensively for cloud deployment, containerization, and enhanced security.
