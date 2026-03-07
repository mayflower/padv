FROM php:8.5-apache

# Install gd extension
RUN set -x \
 && buildDeps="libpng-dev libjpeg-dev libfreetype6-dev" \
 && apt-get update && apt-get install -y ${buildDeps} --no-install-recommends \
 && docker-php-ext-configure gd --with-freetype=/usr/include/ --with-jpeg=/usr/include/ \
 && docker-php-ext-install gd \
 && apt-get purge -y ${buildDeps} \
 && rm -rf /var/lib/apt/lists/*

# Install ldap extension
RUN set -x \
 && buildDeps="libldap2-dev" \
 && apt-get update && apt-get install -y ${buildDeps} --no-install-recommends \
 && docker-php-ext-install ldap \
 && apt-get purge -y ${buildDeps} \
 && rm -rf /var/lib/apt/lists/*

# Install intl and zip
RUN set -x \
 && buildDeps="libicu-dev zlib1g-dev libxml2-dev libzip-dev" \
 && apt-get update && apt-get install -y ${buildDeps} --no-install-recommends \
 && docker-php-ext-configure intl \
 && docker-php-ext-install intl zip \
 && docker-php-ext-enable opcache || true \
 && apt-get purge -y ${buildDeps} \
 && rm -rf /var/lib/apt/lists/*

# Install mysql + postgres drivers
RUN set -x \
 && docker-php-ext-install pdo pdo_mysql mysqli

RUN set -ex \
 && buildDeps="libpq-dev" \
 && apt-get update && apt-get install -y ${buildDeps} \
 && docker-php-ext-configure pgsql -with-pgsql=/usr/local/pgsql \
 && docker-php-ext-install pdo pdo_pgsql pgsql \
 && apt-get purge -y ${buildDeps} \
 && rm -rf /var/lib/apt/lists/*

# Install xdebug + redis as in upstream dev image
RUN pecl install xdebug-3.5.0 && docker-php-ext-enable xdebug
RUN pecl install redis-6.3.0 && docker-php-ext-enable redis

# Install Morcilla extension from synced sources
COPY targets/phpMyFAQ/.docker/morcilla/ext/morcilla /usr/src/php/ext/morcilla
RUN docker-php-ext-install morcilla \
 && docker-php-ext-enable morcilla \
 && { \
      echo '; morcilla scanner configuration'; \
      echo 'morcilla.key=test-key'; \
    } > "$PHP_INI_DIR/conf.d/zz-morcilla.ini"

ENV PMF_TIMEZONE="Europe/Berlin" \
    PMF_ENABLE_UPLOADS=On \
    PMF_MEMORY_LIMIT=2048M \
    DISABLE_HTACCESS="" \
    PHP_LOG_ERRORS=On \
    PHP_ERROR_REPORTING=E_ALL \
    PHP_POST_MAX_SIZE=64M \
    PHP_UPLOAD_MAX_FILESIZE=64M

RUN a2enmod ssl && a2enmod rewrite \
 && mkdir -p /etc/apache2/ssl

COPY targets/phpMyFAQ/.docker/*.pem /etc/apache2/ssl/
COPY targets/phpMyFAQ/.docker/apache/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY targets/phpMyFAQ/.docker/apache/docker-entrypoint.sh /entrypoint

RUN chmod +x /entrypoint
ENTRYPOINT ["/entrypoint"]
CMD ["apache2-foreground"]
