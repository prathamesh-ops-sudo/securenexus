#!/bin/bash
set -euo pipefail

CLUSTER_NAME="${EKS_CLUSTER:-securenexus}"
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REPO="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/securenexus"

log() { echo "[setup] $(date -u +%Y-%m-%dT%H:%M:%SZ) $1"; }

log "=== SecureNexus EKS Setup ==="
log "Cluster: ${CLUSTER_NAME} | Region: ${REGION} | Account: ${ACCOUNT_ID}"

log "Step 1/7: Updating kubeconfig..."
aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$REGION"

log "Step 2/7: Creating namespaces..."
kubectl apply -f k8s/base/namespace.yml

log "Step 3/7: Installing Argo Rollouts..."
kubectl create namespace argo-rollouts --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -n argo-rollouts -f https://github.com/argoproj/argo-rollouts/releases/latest/download/install.yaml

log "Step 4/7: Applying network policies..."
kubectl apply -f k8s/base/network-policy.yml

log "Step 5/7: Syncing secrets from AWS Secrets Manager..."
for ENV in staging uat production; do
  SECRET_ID="securenexus/${ENV}"
  if aws secretsmanager describe-secret --secret-id "$SECRET_ID" --region "$REGION" >/dev/null 2>&1; then
    SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ID" --query SecretString --output text)
    kubectl create secret generic securenexus-secrets \
      --namespace="$ENV" \
      --from-literal="DATABASE_URL=$(echo "$SECRET_JSON" | jq -r '.DATABASE_URL')" \
      --from-literal="SESSION_SECRET=$(echo "$SECRET_JSON" | jq -r '.SESSION_SECRET')" \
      --from-literal="S3_BUCKET_NAME=$(echo "$SECRET_JSON" | jq -r '.S3_BUCKET_NAME // empty')" \
      --from-literal="AWS_REGION=$(echo "$SECRET_JSON" | jq -r '.AWS_REGION // "us-east-1"')" \
      --dry-run=client -o yaml | kubectl apply -f -
    log "  Synced secrets for ${ENV}"
  else
    log "  WARNING: Secret ${SECRET_ID} not found - skipping ${ENV}"
  fi
done

log "Step 6/7: Deploying monitoring stack..."
kubectl apply -f k8s/monitoring/alerting-rules.yml
kubectl apply -f k8s/monitoring/prometheus.yml
kubectl apply -f k8s/monitoring/grafana.yml

log "Step 7/7: Applying production PDB..."
kubectl apply -f k8s/production/pdb.yml

log "=== Setup Complete ==="
log "Namespaces: staging, uat, production, argo-rollouts, monitoring"
log "Argo Rollouts: installed"
log "Monitoring: Prometheus + Grafana with alerting rules"
log "Network Policies: applied to all environments"
log ""
log "Next: Push image to ECR and deploy:"
log "  docker build -t ${ECR_REPO}:latest ."
log "  aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${ECR_REPO%%/*}"
log "  docker push ${ECR_REPO}:latest"
log "  export IMAGE=${ECR_REPO}:latest"
log "  envsubst < k8s/staging/rollout.yml | kubectl apply -f - && kubectl apply -f k8s/staging/service.yml"
