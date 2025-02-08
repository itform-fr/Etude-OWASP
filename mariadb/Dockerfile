# Utiliser l'image officielle PHP avec Apache
FROM mariadb:latest

# Définir les variables d'environnement
ENV MYSQL_ROOT_PASSWORD=poseidon
ENV MYSQL_DATABASE=vuln_site

COPY ./vuln_site.sql /docker-entrypoint-initdb.d/
