# ICT171 Presentation Deployment

**Student:** Alex Quartermaine  
**Student ID:** 35403093  
**Unit:** ICT171 – Introduction to Server Environments and Architectures (S1, 2025)

This subproject contains the complete Docker-based deployment of my presentation website. It is deployed locally using NGINX and mapped to a custom port.

## Overview

This project demonstrates:

- A static HTML presentation page
- Docker containerization for modular deployment
- NGINX configuration with a custom port mapping
- Local development and deployment

**Accessible at:** http://quartzcs.com:8181

## Directory Structure

presentation-deployment/  
├── docker-compose.yml              # Launches NGINX container  
├── nginx/  
│   └── default.conf                # NGINX configuration for static file serving  
├── app/  
│   └── index.html                  # Presentation HTML file  
├── Dockerfile                      # Docker build instructions  
├── build_and_run.sh                # Helper script for build and launch  
└── README.md                       # This file  

## Deployment Workflow

1. **Build the image:**
```bash
docker build -t ict171-presentation .
```

2. **Deploy the container:**
```bash
docker run -d --name ict171-proposal -p 8181:80 ict171-presentation
```

> The presentation will be accessible at http://localhost:8181

## Technologies Used

- HTML5/CSS3
- NGINX
- Docker
- Ubuntu 24.10

## Template Attribution

This project was built manually and does not use a third-party HTML template.
