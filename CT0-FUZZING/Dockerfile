FROM httpd:latest

# Force Bash shell
SHELL ["/bin/bash", "-c"]
RUN sed -i '/.ht*/,+2 s/denied/granted/;/httpd-vhosts.conf/ s/^#//' conf/httpd.conf
# Create necessary directories
RUN mkdir -p /usr/local/apache2/docs/{goodluck,void,blogger} \
    && mkdir -p /usr/local/apache2/docs/goodluck/{dev,public} \
    && mkdir -p /usr/local/apache2/docs/blogger/{api,public}

# Create the HTML files and other text files
RUN echo "<!DOCTYPE html><html><title>GoodLuck</title><body><H1 style=text-align:center;color:blue;margin-top:40vh>GoodLuck.lab</H1></body></html>" > /usr/local/apache2/docs/goodluck/public/index.html \
    && echo "<!DOCTYPE html><html><title>blogger</title><body><H1 style=text-align:center;color:blue;margin-top:40vh>Blogger.lab</H1></body></html>" > /usr/local/apache2/docs/blogger/public/index.html \
    && echo "TopSecret" > /usr/local/apache2/docs/goodluck/dev/secret.txt \
    && echo "bob:$apr1$Er7kbyRS$z/CmchF4WI6yr8PB628kY." > /usr/local/apache2/docs/blogger/api/.htpasswd \
    && echo "hahaha" > /usr/local/apache2/docs/void/nothing.txt

# Change ownership of the created files and directories
RUN chown -R www-data:www-data /usr/local/apache2/docs

# Modify the httpd-vhosts.conf file
RUN echo -e "<VirtualHost _default_:80>\n\
    ServerAdmin admin@goodluck.lab\n\
    DocumentRoot \"/usr/local/apache2/htdocs\"\n\
    ErrorLog \"logs/error_log\"\n\
    CustomLog \"logs/access_log\" common\n\
</VirtualHost>\n\
<VirtualHost *:80>\n\
    ServerAdmin admin@goodluck.lab\n\
    DocumentRoot \"/usr/local/apache2/docs/goodluck/public\"\n\
    ServerName goodluck.lab\n\
    ServerAlias www.goodluck.lab\n\
    ErrorLog \"logs/goodluck_error_log\"\n\
    CustomLog \"logs/goodluck-access_log\" common\n\
</VirtualHost>\n\
<VirtualHost *:80>\n\
    ServerAdmin admin@goodluck.lab\n\
    DocumentRoot \"/usr/local/apache2/docs/goodluck/dev\"\n\
    ServerName dev.goodluck.lab\n\
    ErrorLog \"logs/dev.goodluck-error_log\"\n\
    CustomLog \"logs/dev.goodluck-access_log\" common\n\
</VirtualHost>\n\
<VirtualHost *:80>\n\
    ServerAdmin admin@blogger.lab\n\
    DocumentRoot \"/usr/local/apache2/docs/blogger/public\"\n\
    ServerName blogger.lab\n\
    ServerAlias www.blogger.lab\n\
    ErrorLog \"logs/blogger-error_log\"\n\
    CustomLog \"logs/blogger-access_log\" common\n\
</VirtualHost>\n\
<VirtualHost *:80>\n\
    ServerAdmin admin@blogger.lab\n\
    DocumentRoot \"/usr/local/apache2/docs/blogger/api\"\n\
    ServerName api.blogger.lab\n\
    ErrorLog \"logs/api.blogger-error_log\"\n\
    CustomLog \"logs/api.blogger-access_log\" common\n\
</VirtualHost>\n\
<VirtualHost *:80>\n\
    ServerAdmin admin@blogger.lab\n\
    DocumentRoot \"/usr/local/apache2/docs/void\"\n\
    ServerName void.lab\n\
    ServerAlias www.void.lab\n\
    ErrorLog \"logs/void-error_log\"\n\
    CustomLog \"logs/void-access_log\" common\n\
</VirtualHost>" > /usr/local/apache2/conf/extra/httpd-vhosts.conf

RUN echo -e "<Directory /usr/local/apache2/docs>\n\tRequire all granted\n</Directory>" >> /usr/local/apache2/conf/httpd.conf
