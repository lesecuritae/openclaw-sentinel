FROM node:22-alpine AS frontend-builder
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml ./
COPY core ./core
COPY collectors ./collectors
COPY engine ./engine
COPY actions ./actions
COPY intelligence ./intelligence
COPY llm ./llm
COPY mcp ./mcp
COPY database ./database
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim
RUN groupadd --system sentinel && useradd --system --gid sentinel --home /app sentinel
WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels
COPY --chown=sentinel:sentinel config /app/config
COPY --from=frontend-builder /frontend/dist /app/frontend
RUN mkdir /data && chown sentinel:sentinel /data
USER sentinel
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"]
CMD ["uvicorn", "core.app:app", "--host", "0.0.0.0", "--port", "8080"]
