#!/bin/bash

export PORT="7472"
export DB_NAME="authfuck"
export DB_USER="authsec"
export DB_PASSWORD="authsec@kloudone"
export DB_HOST="localhost"
export DB_PORT="5433"
export DB_SCHEMA="public"
export LOG_LEVEL="info"
export GIN_MODE="debug"
export AUTH_MANAGER_URL="http://localhost:7469"
export VAULT_ADDR="http://localhost:8201"
export VAULT_TOKEN="hvs.CAESIEyHKH0hlW-PUg6P_VzIpL-2m1jzDHWPfIGyb3rI4auCGh4KHGh2cy45aHdmWHJjbVVaSU5OeWNXRmhPY1pkNVU"
export HYDRA_ADMIN_URL="http://localhost:4445"

echo "Environment variables set for Unix/Linux environment."
