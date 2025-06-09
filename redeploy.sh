#!/bin/bash

echo "Rebuilding Docker image..."
docker build -t my-cyber-portfolio:final .

echo "Stopping existing container..."
docker stop quartz-nginx-final 2>/dev/null

echo "Removing old container..."
docker rm quartz-nginx-final 2>/dev/null

echo "Starting new container..."
docker run -d --name quartz-nginx-final -p 80:80 -p 443:443 my-cyber-portfolio:final

echo "Deployment complete. Visit https://quartzcs.com"
