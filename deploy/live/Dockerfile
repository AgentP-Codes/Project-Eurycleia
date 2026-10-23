# The live test's agent (deploy/live), built by .github/workflows/live-image.yml. Contains code only: no data, keys
# or settings. Those come from Azure at run time (Key Vault, settings, the /data file share).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    EURYCLEIA_DATA=/data
WORKDIR /app

COPY requirements/runtime.lock requirements/runtime.lock
RUN pip install --require-hashes -r requirements/runtime.lock

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY eurycleia eurycleia
COPY taskvault taskvault
RUN pip install --no-deps .

COPY demo/__init__.py demo/pricing.py demo/results.py demo/
COPY deploy/live deploy/live

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin agent && mkdir -p /data && chown agent /data
USER agent

ENTRYPOINT ["python", "deploy/live/live.py"]
CMD ["once"]
