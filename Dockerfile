FROM ghcr.io/joernio/joern:v4.0.228 AS joerncli

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    COMPOSER_ALLOW_SUPERUSER=1 \
    PYTHONPATH=/workspace/haxor \
    PATH=/root/.composer/vendor/bin:/root/.config/composer/vendor/bin:${PATH}

WORKDIR /workspace/haxor

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    default-jre-headless \
    git \
    golang-go \
    nodejs \
    npm \
    php-cli \
    composer \
    && rm -rf /var/lib/apt/lists/*

COPY --from=joerncli /opt/joern /opt/joern

ENV PATH=/opt/joern/joern-cli:${PATH}

COPY pyproject.toml README.md /workspace/haxor/
COPY docker /workspace/haxor/docker
RUN python -c "import pathlib, tomllib; payload = tomllib.loads(pathlib.Path('/workspace/haxor/pyproject.toml').read_text(encoding='utf-8')); pathlib.Path('/tmp/requirements.txt').write_text('\\n'.join(payload.get('project', {}).get('dependencies', [])) + '\\n', encoding='utf-8')" \
    && pip install --upgrade pip && pip install -r /tmp/requirements.txt \
    && playwright install --with-deps chromium \
    && GOBIN=/usr/local/bin go install github.com/sourcegraph/scip/cmd/scip@latest \
    && rm -rf /opt/scip-php \
    && git clone --depth 1 https://github.com/davidrjenni/scip-php.git /opt/scip-php \
    && git -C /opt/scip-php apply /workspace/haxor/docker/scip-loader.patch \
    && git -C /opt/scip-php apply /workspace/haxor/docker/scip-symbolnamer.patch \
    && composer install --working-dir /opt/scip-php --no-interaction --prefer-dist --no-dev \
    && ln -sf /opt/scip-php/bin/scip-php /usr/local/bin/scip-php

ENTRYPOINT ["python", "-m", "padv.cli.main"]
CMD ["--help"]
