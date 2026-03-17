#!/bin/bash
# Shopist deployment script
# WARNING: intentionally contains hardcoded secrets for Secret Scanning demo

# AWS credentials
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

# Docker Hub login
DOCKER_HUB_TOKEN="dckr_pat_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abc"
echo "$DOCKER_HUB_TOKEN" | docker login --username shopist --password-stdin

# GitHub token for pulling private packages
GH_TOKEN="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789"
git config --global url."https://${GH_TOKEN}@github.com/".insteadOf "https://github.com/"

# Helm / Kubernetes deployment
KUBE_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzaG9waXN0LWRlcGxveSIsImlhdCI6MTYwMDAwMDAwMH0.fake_signature_for_demo"
kubectl config set-credentials shopist-deploy --token="$KUBE_TOKEN"

# Vault token for secrets
VAULT_TOKEN="hvs.aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcde"
vault login "$VAULT_TOKEN"

# Notify Slack
SLACK_WEBHOOK="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
curl -X POST "$SLACK_WEBHOOK" -d '{"text":"Shopist deployment started"}'

# Run database migrations
DATABASE_URL="postgresql://shopist_admin:Sup3rS3cr3tP@ssw0rd!@prod-db.shopist.internal:5432/shopist"
psql "$DATABASE_URL" -f migrations/latest.sql

echo "Deployment complete"
