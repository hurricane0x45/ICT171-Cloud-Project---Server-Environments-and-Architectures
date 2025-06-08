FROM nginx:latest
LABEL authors="Alex Quartermaine"

# Public content only
COPY app/public /usr/share/nginx/html

# Secure: copy private, but not in webroot
COPY app/private/js /opt/app-private/js

# Custom NGINX config
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx/public.conf /etc/nginx/conf.d/


# SSL mount ready
COPY nginx/ssl /etc/letsencrypt

EXPOSE 80
EXPOSE 443

CMD ["nginx", "-g", "daemon off;"]
