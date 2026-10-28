# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    CNAMSIGN_PATH=/opt/cnamsign \
    DATA_DIR=/data \
    DATABASE_URL=sqlite:////data/cnamsign.db

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates tesseract-ocr \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1) Dépendances de l'application (changent rarement : couche mise en cache)
COPY requirements.txt .
RUN pip install -r requirements.txt

# 2) Code upstream CnamSign, intégré tel quel (pas de fork).
#    Mise à jour : docker compose build --build-arg CNAMSIGN_CACHEBUST=$(date +%s)
#    Version figée : --build-arg CNAMSIGN_REF=<sha ou tag>
ARG CNAMSIGN_REPO=https://github.com/ndh51/CnamSign.git
ARG CNAMSIGN_REF=main
ARG CNAMSIGN_CACHEBUST=0
RUN echo "cnamsign cache-bust: ${CNAMSIGN_CACHEBUST}" \
 && git clone --quiet "${CNAMSIGN_REPO}" "${CNAMSIGN_PATH}" \
 && git -C "${CNAMSIGN_PATH}" checkout --quiet "${CNAMSIGN_REF}" \
 && git -C "${CNAMSIGN_PATH}" rev-parse HEAD > "${CNAMSIGN_PATH}/REVISION" \
 && rm -rf "${CNAMSIGN_PATH}/.git" \
 && pip install -r "${CNAMSIGN_PATH}/requirements.txt" \
 && python -m playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/*

# 3) Code de l'application, exécuté en utilisateur non root
RUN useradd --create-home --uid 1000 app && mkdir -p /data && chown app:app /data
COPY --chown=app:app app ./app
USER app

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" || exit 1

# Un seul worker uvicorn : le planificateur APScheduler vit dans le processus.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--workers", "1"]
