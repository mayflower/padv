FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    COMPOSER_ALLOW_SUPERUSER=1 \
    PATH=/root/.composer/vendor/bin:/root/.config/composer/vendor/bin:${PATH}

WORKDIR /workspace/haxor

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    golang-go \
    nodejs \
    npm \
    php-cli \
    composer \
    && rm -rf /var/lib/apt/lists/*

COPY . /workspace/haxor
RUN pip install --upgrade pip && pip install -e . \
    && playwright install --with-deps chromium \
    && GOBIN=/usr/local/bin go install github.com/sourcegraph/scip/cmd/scip@latest \
    && rm -rf /opt/scip-php \
    && git clone --depth 1 https://github.com/davidrjenni/scip-php.git /opt/scip-php \
    && git -C /opt/scip-php apply /workspace/haxor/docker/scip-loader.patch \
    && git -C /opt/scip-php apply /workspace/haxor/docker/scip-symbolnamer.patch \
    && composer install --working-dir /opt/scip-php --no-interaction --prefer-dist --no-dev \
    && ln -sf /opt/scip-php/bin/scip-php /usr/local/bin/scip-php

ENTRYPOINT ["padv"]
CMD ["--help"]
