# Supported base image, rebuilt regularly (F04/F17, CWE-1104)
FROM php:8.3-apache

COPY ./web-app/ /var/www/html/
COPY ./api/     /var/www/html/api/
COPY ./cgi-bin/ /usr/lib/cgi-bin/

RUN chmod +x /usr/lib/cgi-bin/status_check \
 && docker-php-ext-install pdo_mysql \
 && a2enmod rewrite cgi \
 && chown -R www-data:www-data /var/www

# Health check so the orchestrator can see the container is alive (F15)
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD php -r 'exit(@fsockopen("localhost", 80) ? 0 : 1);'

# Drop root: run the web server as an unprivileged user (F12, CWE-250)
USER www-data

EXPOSE 80
