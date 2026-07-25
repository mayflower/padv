# Build context is assembled by tests/test_morcilla_extension_contract.py:
# it copies the morcilla extension source to ext/morcilla and probe.php next to
# this file. Mirrors docker/mutillidae/www-morcilla.Dockerfile, minus the parts
# the header contract does not need (database, ldap, apache site config).
FROM php:apache

COPY ext/morcilla /usr/src/php/ext/morcilla
RUN docker-php-ext-install morcilla \
 && docker-php-ext-enable morcilla \
 && echo 'morcilla.key=test-key' > "$PHP_INI_DIR/conf.d/zz-morcilla.ini"

COPY probe.php /var/www/html/probe.php
