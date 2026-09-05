FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS frontend-builder
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend ./
RUN npm run build

FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS builder
WORKDIR /build
ENV SOURCE_DATE_EPOCH=1788480000 PYTHONHASHSEED=0
COPY requirements.lock requirements-build.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements-build.lock && \
    pip download --only-binary=:all: --require-hashes -r requirements.lock -d /wheels
COPY pyproject.toml ./
COPY core ./core
COPY collectors ./collectors
COPY engine ./engine
COPY actions ./actions
COPY intelligence ./intelligence
COPY llm ./llm
COPY mcp ./mcp
COPY database ./database
RUN pip wheel --no-deps --no-build-isolation --wheel-dir /wheels .

FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
RUN groupadd --system sentinel && useradd --system --gid sentinel --home /app sentinel
WORKDIR /app
COPY --from=builder /wheels /wheels
COPY requirements.lock /app/requirements.lock
RUN pip install --no-index --find-links=/wheels --require-hashes -r requirements.lock && \
    pip install --no-index --no-deps /wheels/openclaw_sentinel-*.whl && rm -rf /wheels
COPY --chown=sentinel:sentinel config /app/config
COPY --from=frontend-builder /frontend/dist /app/frontend
RUN mkdir /data && chown sentinel:sentinel /data
USER sentinel
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"]
CMD ["uvicorn", "core.app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--ws-max-size", "4096", "--limit-concurrency", "100"]
