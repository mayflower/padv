FROM php:apache

RUN apt-get update \
 && apt-get install --no-install-recommends -y \
      dnsutils \
      iputils-ping \
      libcurl4-openssl-dev \
      libldap2-dev \
      libonig-dev \
      libxml2-dev \
      ntpsec \
 && docker-php-ext-install ldap xml mbstring curl mysqli \
 && rm -rf /var/lib/apt/lists/*

COPY targets/mutillidae/.docker/morcilla/ext/morcilla /usr/src/php/ext/morcilla
RUN docker-php-ext-install morcilla \
 && docker-php-ext-enable morcilla \
 && { \
      echo '; morcilla scanner configuration'; \
      echo 'morcilla.key=test-key'; \
    } > "$PHP_INI_DIR/conf.d/zz-morcilla.ini"

COPY targets/mutillidae/src /var/www/mutillidae
RUN mkdir -p /var/www/mutillidae/data /var/www/mutillidae/passwords \
 && chown -R www-data:www-data /var/www/mutillidae/data /var/www/mutillidae/passwords \
 && chmod -R 775 /var/www/mutillidae/data /var/www/mutillidae/passwords \
 && rm -f /var/www/mutillidae/.htaccess

RUN cp /usr/local/etc/php/php.ini-development /usr/local/etc/php/php.ini \
 && sed -i 's/allow_url_include = Off/allow_url_include = On/g' /usr/local/etc/php/php.ini \
 && sed -i 's/allow_url_fopen = Off/allow_url_fopen = On/g' /usr/local/etc/php/php.ini \
 && sed -i 's/expose_php = On/expose_php = On/g' /usr/local/etc/php/php.ini \
 && sed -i 's/^error_reporting = .*/error_reporting = E_ALL/' /usr/local/etc/php/php.ini \
 && sed -i 's/^display_errors = .*/display_errors = On/' /usr/local/etc/php/php.ini

RUN sed -i "s/define('DB_HOST', '127.0.0.1');/define('DB_HOST', 'database');/" /var/www/mutillidae/includes/database-config.inc \
 && sed -i "s/define('DB_USERNAME', 'root');/define('DB_USERNAME', 'root');/" /var/www/mutillidae/includes/database-config.inc \
 && sed -i "s/define('DB_PASSWORD', 'mutillidae');/define('DB_PASSWORD', 'mutillidae');/" /var/www/mutillidae/includes/database-config.inc \
 && sed -i "s/define('DB_NAME', 'mutillidae');/define('DB_NAME', 'mutillidae');/" /var/www/mutillidae/includes/database-config.inc \
 && sed -i "s/define('DB_PORT', 3306);/define('DB_PORT', 3306);/" /var/www/mutillidae/includes/database-config.inc \
 && sed -i "s/define('LDAP_HOST', '127.0.0.1');/define('LDAP_HOST', 'directory');/" /var/www/mutillidae/includes/ldap-config.inc

RUN mkdir -p /etc/apache2/conf /etc/apache2/error-pages
COPY targets/mutillidae-docker/.build/www/configuration/https-certificate/mutillidae-selfsigned.crt /etc/ssl/certs/mutillidae-selfsigned.crt
COPY targets/mutillidae-docker/.build/www/configuration/https-certificate/mutillidae-selfsigned.key /etc/ssl/private/mutillidae-selfsigned.key
COPY targets/mutillidae-docker/.build/www/configuration/apache-configuration/conf/error-pages.conf /etc/apache2/conf/error-pages.conf
COPY targets/mutillidae-docker/.build/www/configuration/apache-configuration/conf/headers.conf /etc/apache2/conf/headers.conf
COPY targets/mutillidae-docker/.build/www/configuration/apache-configuration/error-pages/404.html /etc/apache2/error-pages/404.html
COPY targets/mutillidae-docker/.build/www/configuration/apache-configuration/error-pages/oops.jpg /etc/apache2/error-pages/oops.jpg
COPY targets/mutillidae-docker/.build/www/configuration/apache-configuration/conf-available/aliases.conf /etc/apache2/conf-available/aliases.conf
COPY targets/mutillidae-docker/.build/www/configuration/apache-configuration/sites-available/mutillidae.conf /etc/apache2/sites-available/mutillidae.conf

RUN sed -i 's/127.0.0.1/0.0.0.0/g' /etc/apache2/sites-available/mutillidae.conf \
 && sed -i 's/127.0.0.2/0.0.0.0/g' /etc/apache2/sites-available/mutillidae.conf \
 && a2enmod ssl \
 && a2dissite 000-default \
 && a2ensite mutillidae

EXPOSE 80 443
