# LEMP Stack

Setup script used to deploy LEMP with Lets Encrypt on Debian.

## Usage

The following installs Nginx with PHP and MariaDB and creates a site with certificate from Lets Encrypt. Run it as root, and make sure firewalls and DNS is already done as this is needed to validate domain ownership for Lets Encrypt.

```bash
# Define variables
export DOMAIN=domain
export SQLPASSWORD=sqlpass
export EMAIL=email

# Download and run script
curl -s -L https://raw.githubusercontent.com/jonasmagnusson/lemp-stack/main/setup.sh | bash
```

## Packages

The following packages are installed:

* certbot
* mariadb-client
* mariadb-server
* nginx
* php
* php-curl
* php-fpm
* php-gd
* php-mysql
* python-certbot-nginx