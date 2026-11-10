FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Runs without root privileges (least privilege). The model folder is writable because
# the WAF trains a model on first start when no signed model file exists.
RUN useradd --create-home waf && mkdir -p models && chown -R waf:waf /srv
USER waf

# Header handling stays off in uvicorn: the WAF resolves client IPs using TRUST_PROXY_HOPS.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --no-proxy-headers --no-server-header"]
