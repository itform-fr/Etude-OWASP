# Utiliser l'image officielle PHP avec Apache
FROM php:8.3-apache

# Installer l'extension PHP pour MySQL
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Configurer Apache pour pointer vers le dossier /var/www/html/images
RUN echo "<Directory /var/www/html/images>" >> /etc/apache2/apache2.conf \
    && echo "    Options +Indexes" >> /etc/apache2/apache2.conf \
    && echo "    AllowOverride All" >> /etc/apache2/apache2.conf \
    && echo "</Directory>" >> /etc/apache2/apache2.conf

# Copier les fichiers de votre projet web dans le conteneur (dossier local à adapter)
COPY web.tar.gz /tmp/web.tar.gz
RUN tar -xvzf /tmp/web.tar.gz -C /var/www/html
RUN rm /tmp/web.tar.gz
COPY ./web /var/www/html

