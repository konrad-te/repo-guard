FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples

RUN pip install --upgrade pip \
    && pip install -e . \
    && pip install bandit pip-audit semgrep pip-licenses \
    && curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
      | sh -s -- -b /usr/local/bin

VOLUME ["/app/reports"]
ENTRYPOINT ["repoguard"]
CMD ["scan"]
