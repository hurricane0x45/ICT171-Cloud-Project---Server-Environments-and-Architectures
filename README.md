# ICT171 Cloud Project – Portfolio + Proposal

**Student** Alex Quartermaine  
**Student ID:** 35403093  
**Unit:** ICT171 – Introduction to Server Environments and Architectures (S1, 2025)  

This repository contains two subprojects submitted for ICT171 – *Introduction to Server Environments and Architectures* (Semester 1, 2025):

1. **MY-Cyber-Portfolio/** – a professional static web portfolio hosted via Docker + NGINX with SSL.
2. **ict171-proposal/** – the original Assignment 1 project proposal deployed in a separate container.

Both are containerized and deployed from a DigitalOcean IaaS droplet.



## Repository Structure

```
ICT171-Cloud-ProjectServer-Environments-and-Architectures/
├── MY-Cyber-Portfolio/        # Portfolio site with full deployment config
│   └── README.md              # Technical breakdown and build process
│
├── ict171-proposal/           # Assignment 1 HTML/CSS-based proposal
│   └── README.md              # Description of contents and structure
│
├── Presentation/              # Standalone HTML slideshow (runs on port 8181)
│ └── README.md                # Project details and deployment steps
│
├── my-cyber-portfolio.tar     # Final Docker image archive (portfolio)
├── ict171_project_image.tar   # Archived Docker image for proposal
├── quartz-nginx.tar           # Backup image with NGINX config
├── redeploy.sh                # Quick deployment bash script
└── README.md                  # (this file)
```


## 1 – MY Cyber Portfolio

Hosted at: **https://quartzcs.com**
Deployed via: `docker run` with mounted volumes, SSL by Certbot

Features:
- Static HTML/CSS/JS frontend with particle.js animations
- NGINX server configured via custom public.conf
- Secure JavaScript route aliasing
- DNS & HTTPS tested and operational

Details in [`MY-Cyber-Portfolio/README.md`](MY-Cyber-Portfolio_README.md)



## 2 – ICT171 Proposal HTML Site

Accessible at: **http://quartzcs.com:8080**

A self-contained HTML proposal submitted as Assignment 1.
It runs in a separate Docker container (port 8080/8443) for segregation from the portfolio site.

Features:
- HTML landing page styled with CSS
- Responsive and lightweight
- Manual deployment via docker + custom container

Details in [`ict171-proposal/README.md`](ict171-proposal_README.md)


## 3 – HTML Presentation Deployment

**Accessible at:** http://quartzcs.com:8181

This is a minimal HTML presentation (from `complete_presentation_slides.html`) hosted in a separate Docker container to demonstrate Dockerized content delivery.

**Key Features:**
- Runs independently on port `8181`
- Lightweight, fast-loading HTML
- Isolated and easy to redeploy using `build_and_run.sh`

Details in [`Presentation/README.md`](Presentation_README.md)


