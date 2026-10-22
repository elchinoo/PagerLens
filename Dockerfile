FROM python:3.14-slim

WORKDIR /app

# The shared blocks (agentpg-kit), pinned to a release; then the app itself.
ARG KIT_URL=https://github.com/elchinoo/agentpg-kit/archive/refs/tags/v0.2.0.tar.gz
RUN pip install --no-cache-dir "agentpg-kit @ ${KIT_URL}"

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Bind to all interfaces so a reverse proxy / sandbox can reach the app.
# The database connection (DB_EXTERNAL_DSN or DATABASE_URL) is supplied at runtime, never baked in.
ENV HOST=0.0.0.0 \
    PORT=8000 \
    PYTHONUNBUFFERED=1

# psycopg-binary bundles its own OpenSSL, whose default CA path is not Debian's,
# so sslrootcert=system finds no roots. Point it at the system bundle.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN useradd --system --no-create-home app
USER app

EXPOSE 8000

HEALTHCHECK --start-period=30s CMD python -c "import urllib.request,os;urllib.request.urlopen('http://localhost:'+os.environ['PORT']+'/healthz')"

# Migrates on boot (idempotent), optionally seeds when AUTO_SEED=true, then serves.
CMD ["pagerlens", "start"]
