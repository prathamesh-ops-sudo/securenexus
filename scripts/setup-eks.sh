#!/bin/bash
set -euo pipefail

CLUSTER_NAME="securenexus"
REGION="us-east-1"
ECR_REPO="557845624595.dkr.ecr.us-east-1.amazonaws.com/securenexus"

echo "=== SecureNexus EKS Setup ==="

echo "1. Updating kubeconfig..."
aws eks update-kubeconfig --name $CLUSTER_NAME --region $REGION

echo "2. Creating namespaces..."
kubectl apply -f k8s/base/namespace.yml

echo "3. Installing Argo Rollouts..."
kubectl apply -n argo-rollouts -f https://github.com/argoproj/argo-rollouts/releases/latest/download/install.yaml

echo "4. Applying secrets (must be configured first)..."
kubectl apply -f k8s/base/secrets.yml

echo "5. Deploying monitoring stack..."
kubectl apply -f k8s/monitoring/prometheus.yml
kubectl apply -f k8s/monitoring/grafana.yml

echo "6. Setup complete!"
echo "   - Namespaces: staging, production, argo-rollouts, monitoring"
echo "   - Argo Rollouts: installed in argo-rollouts namespace"
echo "   - Monitoring: Prometheus + Grafana in monitoring namespace"
echo ""
echo "Next steps:"
echo "  1. Update k8s/base/secrets.yml with real DATABASE_URL and SESSION_SECRET"
echo "  2. Build and push Docker image: docker build -t $ECR_REPO:latest . && docker push $ECR_REPO:latest"
echo "  3. Deploy staging: export IMAGE=$ECR_REPO:latest && envsubst < k8s/staging/rollout.yml | kubectl apply -f -"
echo "  4. Deploy production: export IMAGE=$ECR_REPO:latest && envsubst < k8s/production/rollout.yml | kubectl apply -f -"
