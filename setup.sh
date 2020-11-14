#!/bin/bash

# Show usage information
usage() { echo -e "Set variables before executing: \n\nexport DOMAIN=domain\nexport SQLPASSWORD=sqlpass\nexport EMAIL=email\n" 1>&2; exit 1; }

# Check required variables
if [ -z "${DOMAIN}" ] || [ -z "${SQLPASSWORD}" ] || [ -z "${EMAIL}" ]; then
    usage
fi

# Install nginx, php and mariadb
apt-get install -y nginx
apt-get install -y php php-fpm php-curl php-gd
apt-get install -y mariadb-server mariadb-client php-mysql

# Secure MySQL
mysql -e "UPDATE mysql.user SET Password=PASSWORD('$SQLPASSWORD') WHERE User='root';"
mysql -e "DELETE FROM mysql.user WHERE User='';"
mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
mysql -e "DROP DATABASE IF EXISTS test;"
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
mysql -e "FLUSH PRIVILEGES"

# Configure PHP
sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' /etc/php/7.3/cli/php.ini

# Create sock file
mkdir /var/run/php-fpm/
touch /var/run/php-fpm/php-fpm.sock

# Remove default site
rm /etc/nginx/sites-enabled/default

# Genereate dhparam
mkdir /etc/nginx/cert
openssl dhparam -out /etc/nginx/cert/dhparam.pem 2048
chmod 600 /etc/nginx/cert/dhparam.pem

# Configure main site
mkdir /usr/share/nginx/$DOMAIN
touch /etc/nginx/sites-enabled/$DOMAIN.conf

# Create HTTP site file
cat << EOT > /etc/nginx/sites-enabled/$DOMAIN.conf
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    root /usr/share/nginx/$DOMAIN;
    index index.php index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }

    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;

    location = /50x.html {
        root /usr/share/nginx/html;
    }

    location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    server_tokens off;

    add_header 'Referrer-Policy' 'no-referrer';
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Feature-Policy "geolocation none; midi none; notifications none; push none; sync-xhr none; microphone none; camera none; magnetometer none; gyroscope none; speaker none; vibrate none; fullscreen none; payment none;";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; object-src 'none'";

    proxy_hide_header X-Powered-By;
    fastcgi_hide_header X-Powered-By;
    add_header Expect-CT 'enforce; max-age=3600';
}
EOT

# Change user and group
chown -R www-data:www-data /usr/share/nginx/$DOMAIN

# Create webroot file
echo "$DOMAIN" > /usr/share/nginx/$DOMAIN/index.html

# Set file and folder permissions
find /usr/share/nginx/$DOMAIN -type d -exec chmod 755 {} \;
find /usr/share/nginx/$DOMAIN -type f -exec chmod 644 {} \;

# Restart services
service nginx restart
service php7.3-fpm restart
service mysql restart

# Install certbot for Letsencrypt
apt-get install -y certbot python-certbot-nginx

# Generate certificates
certbot certonly --nginx --non-interactive --agree-tos -m $EMAIL --domains $DOMAIN

# Add HTTPS to site and make HTTP redirect to it
cat << EOT > /etc/nginx/sites-enabled/$DOMAIN.conf
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    return 301 https://\$host\$request_uri;

    root /usr/share/nginx/$DOMAIN;
    index index.php index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }

    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;

    location = /50x.html {
        root /usr/share/nginx/html;
    }

    location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    server_tokens off;

    add_header 'Referrer-Policy' 'no-referrer';
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Feature-Policy "geolocation none; midi none; notifications none; push none; sync-xhr none; microphone none; camera none; magnetometer none; gyroscope none; speaker none; vibrate none; fullscreen none; payment none;";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; object-src 'none'";

    proxy_hide_header X-Powered-By;
    fastcgi_hide_header X-Powered-By;
    add_header Expect-CT 'enforce; max-age=3600';
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    root /usr/share/nginx/$DOMAIN;
    index index.php index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }

    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;

    location = /50x.html {
        root /usr/share/nginx/html;
    }

    location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    ssl on;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    ssl_session_timeout 180m;
    ssl_session_cache shared:SSL:20m;

    ssl_ciphers ECDH+AESGCM:ECDH+AES256:ECDH+AES128:DHE+AES128:!ADH:!AECDH:!MD5;
    ssl_prefer_server_ciphers on;

    ssl_dhparam /etc/nginx/cert/dhparam.pem;

    server_tokens off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header 'Referrer-Policy' 'no-referrer';
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Feature-Policy "geolocation none; midi none; notifications none; push none; sync-xhr none; microphone none; camera none; magnetometer none; gyroscope none; speaker none; vibrate none; fullscreen none; payment none;";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; object-src 'none'";

    proxy_hide_header X-Powered-By;
    fastcgi_hide_header X-Powered-By;
    add_header Expect-CT 'enforce; max-age=3600';
}
EOT

# Restart services
service nginx restart
service php7.3-fpm restart
service mysql restart
