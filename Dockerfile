# Build React assets in an isolated Node stage.
FROM node:22-alpine AS frontend-build
WORKDIR /frontend
COPY frontend/package.json ./package.json
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# Serve the built React app and FastAPI backend from one origin.
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=10000 \
    ENVIRONMENT=production \
    DATA_DIR=/var/data
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends gosu && rm -rf /var/lib/apt/lists/*     && pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY demo_data/ ./demo_data/
COPY company_template/ ./company_template/
COPY --from=frontend-build /frontend/dist ./frontend/dist
RUN mkdir -p /var/data && useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app /var/data
EXPOSE 10000
CMD ["sh", "-c", "chown appuser:appuser /var/data && exec gosu appuser uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-10000} --proxy-headers --forwarded-allow-ips='*' --workers 1"]
