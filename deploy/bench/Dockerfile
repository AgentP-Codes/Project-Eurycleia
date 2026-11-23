# AgentDojo with a real model, as an Azure job (./setup.sh bench), built by .github/workflows/live-image.yml.
# Code only: no keys or settings. The model is reached with the job's own Azure identity; results go to /data.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    EURYCLEIA_DATA=/data
WORKDIR /app

# every library, AgentDojo's included, at an exact version with its checksum (benchmarks/agentdojo/bench.lock):
# this job signs in as the live test's Azure identity, so nothing unpinned goes into its image
COPY benchmarks/agentdojo/bench.lock benchmarks/agentdojo/bench.lock
RUN pip install --require-hashes -r benchmarks/agentdojo/bench.lock

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY eurycleia eurycleia
COPY taskvault taskvault
RUN pip install --no-deps .

COPY demo/__init__.py demo/pricing.py demo/results.py demo/
COPY benchmarks/agentdojo benchmarks/agentdojo

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin bench && mkdir -p /data && chown bench /data
USER bench

ENTRYPOINT ["python", "benchmarks/agentdojo/bench_job.py"]
