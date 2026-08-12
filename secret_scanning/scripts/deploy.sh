#!/bin/bash
# Shopist deployment script
#
# All credentials MUST be injected at runtime via the environment (e.g. from a
# secrets manager, CI secret store, or Vault agent). This script contains NO
# literal credentials. Do not hardcode secrets here.
set -euo pipefail

# Ensure a required environment variable is set and non-empty; otherwise abort.
require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "ERROR: required environment variable '$name' is not set. " \
         "Inject it at runtime from your secrets manager." >&2
    exit 1
  fi
}

# AWS credentials (expected to be provided by the runtime environment)
require_env AWS_ACCESS_KEY_ID
require_env AWS_SECRET_ACCESS_KEY
export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

# Docker Hub login
require_env DOCKER_HUB_TOKEN
echo "$DOCKER_HUB_TOKEN" | docker login --username "${DOCKER_HUB_USERNAME:-shopist}" --password-stdin

# GitHub token for pulling private packages
require_env GH_TOKEN
git config --global url."https://${GH_TOKEN}@github.com/".insteadOf "https://github.com/"

# Helm / Kubernetes deployment
require_env KUBE_TOKEN
kubectl config set-credentials shopist-deploy --token="$KUBE_TOKEN"

# Vault token for secrets
require_env VAULT_TOKEN
vault login "$VAULT_TOKEN"

# Notify Slack
require_env SLACK_WEBHOOK
curl -X POST "$SLACK_WEBHOOK" -d '{"text":"Shopist deployment started"}'

# Run database migrations
require_env DATABASE_URL
psql "$DATABASE_URL" -f migrations/latest.sql

echo "Deployment complete"
