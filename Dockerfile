# steam-legacy-gateway — container image (alternative to the systemd unit).
#
# Build:    docker build -t steam-legacy-gateway .
# Run:      docker run -d --name gateway --network host \
#             -e STEAM_USERNAME=you -e STEAM_PASSWORD=secret \
#             -v $(pwd)/config:/app/config \
#             steam-legacy-gateway
#
# --network host exposes 27017-27020/443/80 directly (needed by the CM + TLS
# listeners). On a VM that is exactly what we want for a 24/7 bridge.

FROM python:3.12-slim

WORKDIR /app

# build deps for cryptography wheels if the platform lacks them
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gateway/ gateway/
COPY config/ config/

EXPOSE 27017 27018 27019 27020 443 80

# Configure credentials via env (STEAM_USERNAME / STEAM_PASSWORD / STEAM_GUARD_CODE)
CMD ["python", "-m", "gateway", "run"]
