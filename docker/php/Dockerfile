# PHP CLI image used by scripts/*.sh to run the test-suite and operator commands without a local PHP install.
#   docker build -t awshortlink-php:local docker/php
FROM php:8.3-cli-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends libpq-dev libpng-dev libjpeg-dev libfreetype6-dev libicu-dev libonig-dev unzip git postgresql-client \
 && docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j"$(nproc)" gd intl mbstring pdo_pgsql \
 && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer
