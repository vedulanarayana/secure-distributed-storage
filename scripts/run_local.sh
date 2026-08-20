#!/usr/bin/env bash
# Starts all four services locally over plain HTTP for the quick-start demo.
# For the TLS 1.3 self-signed setup, use docker-compose instead (see README).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p data

python -m anomaly.train

NODE_ID=node-1 DB_PATH=data/node-1.db uvicorn storage_node.app:app --port 9001 &
NODE_ID=node-2 DB_PATH=data/node-2.db uvicorn storage_node.app:app --port 9002 &
NODE_ID=node-3 DB_PATH=data/node-3.db uvicorn storage_node.app:app --port 9003 &
METADATA_DB_PATH=data/metadata.db uvicorn metadata_service.app:app --port 9000 &

trap 'kill 0' EXIT
wait
