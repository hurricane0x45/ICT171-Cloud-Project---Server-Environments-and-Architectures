# ICT171 Assignment 1 Proposal Deployment

**Student:** Alex Quartermaine  
**Student ID:** 35403093  
**Unit:** ICT171 – Introduction to Server Environments and Architectures (S1, 2025)

This directory contains the HTML/CSS-based proposal originally submitted for Assignment 1. It is now deployed inside its own Docker container for isolation from the portfolio site.


## Overview

This subproject represents the initial proposal for the ICT171 cloud environment. It is deployed independently on ports 8080 (HTTP) and 8443 (HTTPS) of the same DigitalOcean droplet as the main portfolio.


## Directory Contents

```
ict171-proposal/
├── index.html        # Main HTML proposal
├── style.css         # Basic styling
├── README.md         # This file
```

## Deployment

This site runs in its own NGINX container with a lightweight configuration. It is accessible at:

- **HTTP:** http://quartzcs.com:8080

To deploy, the static files are copied into an NGINX image and exposed via ports 8080 and 8443:

```bash
docker run -d --name ict171-proposal \
  -p 8080:80 -p 8443:443 \
  nginx
```



## Notes

- SSL certificates can be added via Certbot if required for secure delivery.
- This project is static-only and contains no scripting or backend logic.
- Meant for academic demonstration only.



## License

This project is included under the [MIT License](../LICENSE.md).
