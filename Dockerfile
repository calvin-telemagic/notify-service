# The tests run on every build (the final stage copies their marker, so
# BuildKit can't skip this stage).
FROM python:3.12-slim AS test
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY pytest.ini ./
COPY app ./app
COPY tests ./tests
RUN python -m pytest -q -p no:cacheprovider && touch /tests-passed

FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY --from=test /tests-passed /tests-passed
RUN useradd --system --no-create-home notify
USER notify
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"
# --no-access-log: keep request lines (and anything a client puts in a URL) out of the logs.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--proxy-headers"]
