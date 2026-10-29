# syntax=docker/dockerfile:1
# Build from the community directory, never the private parent repository.
ARG PYTHON_IMAGE=python:3.13-slim-bookworm
FROM ${PYTHON_IMAGE} AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY pyproject.toml README.md MANIFEST.in ./
COPY src ./src
RUN python -m pip wheel --wheel-dir /wheels .

FROM builder AS test
RUN python -m pip install '.[dev]'
COPY tests ./tests
COPY examples/config.json ./examples/config.json
COPY tools/init_docker_preview.py ./tools/init_docker_preview.py
COPY Dockerfile .dockerignore compose.yaml ./
RUN python -m pytest -q && ruff check src tests tools/init_docker_preview.py

FROM ${PYTHON_IMAGE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 HOME=/home/douforge
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client ca-certificates \
 && apt-get clean \
 && find /var/lib/apt/lists -mindepth 1 -delete \
 && groupadd --gid 10001 douforge \
 && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin douforge \
 && install -d -m 0700 -o 10001 -g 10001 /data /home/douforge/.ssh
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels dou-forge-mcp \
 && find /wheels -mindepth 1 -delete
USER 10001:10001
WORKDIR /home/douforge
EXPOSE 9384
HEALTHCHECK --interval=15s --timeout=3s --start-period=15s --retries=3 \
 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9384/healthz', timeout=2).read()"]
ENTRYPOINT ["douforge"]
CMD ["--config", "/config/config.json", "--state", "/data", "serve", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "9384"]
