#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
PROJECT_TAG="securenexus-demo"
OWNER_TAG="devin"
MODE="${1:---list}"

if [[ "$MODE" != "--list" && "$MODE" != "--delete" ]]; then
  echo "Usage: $0 [--list|--delete]" >&2
  exit 2
fi

if [[ "$MODE" == "--delete" && "${CONFIRM:-}" != "securenexus-demo" ]]; then
  echo "Refusing deletion. Set CONFIRM=securenexus-demo to continue." >&2
  exit 2
fi

aws_cli() {
  aws --region "$REGION" "$@"
}

echo "Resources tagged Project=$PROJECT_TAG Owner=$OWNER_TAG in $REGION:"

INSTANCE_IDS="$(aws_cli ec2 describe-instances \
  --filters "Name=tag:Project,Values=$PROJECT_TAG" "Name=tag:Owner,Values=$OWNER_TAG" \
  "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[].Instances[].InstanceId' --output text)"
echo "EC2 instances: ${INSTANCE_IDS:-none}"

VPC_IDS="$(aws_cli ec2 describe-vpcs \
  --filters "Name=tag:Project,Values=$PROJECT_TAG" "Name=tag:Owner,Values=$OWNER_TAG" \
  --query 'Vpcs[].VpcId' --output text)"
echo "VPCs: ${VPC_IDS:-none}"

SUBNET_IDS="$(aws_cli ec2 describe-subnets \
  --filters "Name=tag:Project,Values=$PROJECT_TAG" "Name=tag:Owner,Values=$OWNER_TAG" \
  --query 'Subnets[].SubnetId' --output text)"
echo "Subnets: ${SUBNET_IDS:-none}"

ROUTE_TABLE_IDS="$(aws_cli ec2 describe-route-tables \
  --filters "Name=tag:Project,Values=$PROJECT_TAG" "Name=tag:Owner,Values=$OWNER_TAG" \
  --query 'RouteTables[].RouteTableId' --output text)"
echo "Route tables: ${ROUTE_TABLE_IDS:-none}"

IGW_IDS="$(aws_cli ec2 describe-internet-gateways \
  --filters "Name=tag:Project,Values=$PROJECT_TAG" "Name=tag:Owner,Values=$OWNER_TAG" \
  --query 'InternetGateways[].InternetGatewayId' --output text)"
echo "Internet gateways: ${IGW_IDS:-none}"

SECURITY_GROUP_IDS="$(aws_cli ec2 describe-security-groups \
  --filters "Name=tag:Project,Values=$PROJECT_TAG" "Name=tag:Owner,Values=$OWNER_TAG" \
  --query 'SecurityGroups[].GroupId' --output text)"
echo "Security groups: ${SECURITY_GROUP_IDS:-none}"

KEY_NAMES="$(aws_cli ec2 describe-key-pairs \
  --filters "Name=tag:Project,Values=$PROJECT_TAG" "Name=tag:Owner,Values=$OWNER_TAG" \
  --query 'KeyPairs[].KeyName' --output text)"
echo "Key pairs: ${KEY_NAMES:-none}"

TRAIL_NAMES=""
for trail_arn in $(aws_cli cloudtrail list-trails --query 'Trails[].TrailARN' --output text); do
  trail_tags="$(aws_cli cloudtrail list-tags --resource-id-list "$trail_arn" --query 'ResourceTagList[0].TagsList' \
    --output json 2>/dev/null || echo '[]')"
  if jq -e --arg project "$PROJECT_TAG" --arg owner "$OWNER_TAG" \
    'any(.[]; .Key == "Project" and .Value == $project) and any(.[]; .Key == "Owner" and .Value == $owner)' \
    <<<"$trail_tags" >/dev/null; then
    TRAIL_NAMES+="${trail_arn##*/}"$'\n'
  fi
done
echo "CloudTrail trails: ${TRAIL_NAMES:-none}"

BUCKET_NAMES=""
for bucket in $(aws_cli s3api list-buckets --query 'Buckets[].Name' --output text); do
  tags="$(aws_cli s3api get-bucket-tagging --bucket "$bucket" --query 'TagSet' --output json 2>/dev/null || echo '[]')"
  if jq -e --arg project "$PROJECT_TAG" --arg owner "$OWNER_TAG" \
    'any(.[]; .Key == "Project" and .Value == $project) and any(.[]; .Key == "Owner" and .Value == $owner)' \
    <<<"$tags" >/dev/null; then
    BUCKET_NAMES+="${bucket}"$'\n'
  fi
done
echo "S3 buckets: ${BUCKET_NAMES:-none}"

ROLE_NAMES=""
for role_name in $(aws_cli iam list-roles --query 'Roles[].RoleName' --output text); do
  role_tags="$(aws_cli iam list-role-tags --role-name "$role_name" --query 'Tags' --output json 2>/dev/null || echo '[]')"
  if jq -e --arg project "$PROJECT_TAG" --arg owner "$OWNER_TAG" \
    'any(.[]; .Key == "Project" and .Value == $project) and any(.[]; .Key == "Owner" and .Value == $owner)' \
    <<<"$role_tags" >/dev/null; then
    ROLE_NAMES+="${role_name}"$'\n'
  fi
done
echo "IAM roles: ${ROLE_NAMES:-none}"

USER_NAMES=""
for user_name in $(aws_cli iam list-users --query 'Users[].UserName' --output text); do
  user_tags="$(aws_cli iam list-user-tags --user-name "$user_name" --query 'Tags' --output json 2>/dev/null || echo '[]')"
  if jq -e --arg project "$PROJECT_TAG" --arg owner "$OWNER_TAG" \
    'any(.[]; .Key == "Project" and .Value == $project) and any(.[]; .Key == "Owner" and .Value == $owner)' \
    <<<"$user_tags" >/dev/null; then
    USER_NAMES+="${user_name}"$'\n'
  fi
done
echo "IAM users: ${USER_NAMES:-none}"

if [[ "$MODE" == "--list" ]]; then
  exit 0
fi

if [[ -n "$INSTANCE_IDS" ]]; then
  aws_cli ec2 terminate-instances --instance-ids $INSTANCE_IDS >/dev/null
  aws_cli ec2 wait instance-terminated --instance-ids $INSTANCE_IDS
fi

for key_name in $KEY_NAMES; do
  aws_cli ec2 delete-key-pair --key-name "$key_name"
done

for sg_id in $SECURITY_GROUP_IDS; do
  aws_cli ec2 delete-security-group --group-id "$sg_id" || true
done

for subnet_id in $SUBNET_IDS; do
  aws_cli ec2 delete-subnet --subnet-id "$subnet_id"
done

for route_table_id in $ROUTE_TABLE_IDS; do
  association_ids="$(aws_cli ec2 describe-route-tables --route-table-ids "$route_table_id" \
    --query 'RouteTables[0].Associations[?Main==`false`].RouteTableAssociationId' --output text)"
  for association_id in $association_ids; do
    aws_cli ec2 disassociate-route-table --association-id "$association_id"
  done
  aws_cli ec2 delete-route-table --route-table-id "$route_table_id"
done

for igw_id in $IGW_IDS; do
  for vpc_id in $VPC_IDS; do
    aws_cli ec2 detach-internet-gateway --internet-gateway-id "$igw_id" --vpc-id "$vpc_id" || true
  done
  aws_cli ec2 delete-internet-gateway --internet-gateway-id "$igw_id"
done

for vpc_id in $VPC_IDS; do
  aws_cli ec2 delete-vpc --vpc-id "$vpc_id"
done

for trail_name in $TRAIL_NAMES; do
  aws_cli cloudtrail stop-logging --name "$trail_name" || true
  aws_cli cloudtrail delete-trail --name "$trail_name"
done

while read -r bucket; do
  [[ -z "$bucket" ]] && continue
  aws_cli s3 rm "s3://$bucket" --recursive
  while read -r batch; do
    [[ -z "$batch" ]] && continue
    aws_cli s3api delete-objects --bucket "$bucket" --delete "$batch" >/dev/null
  done < <(
    aws_cli s3api list-object-versions --bucket "$bucket" --output json |
      jq -c '[.Versions[]?, .DeleteMarkers[]?] | map({Key, VersionId}) | . as $items |
        range(0; ($items | length); 1000) as $offset |
        {Objects: ($items[$offset:$offset+1000]), Quiet: true}'
  )
  aws_cli s3api delete-bucket --bucket "$bucket"
done <<<"$BUCKET_NAMES"

for role_name in $ROLE_NAMES; do
  policy_arns="$(aws_cli iam list-role-policies --role-name "$role_name" --query 'PolicyNames[]' --output text)"
  for policy_name in $policy_arns; do
    aws_cli iam delete-role-policy --role-name "$role_name" --policy-name "$policy_name"
  done
  aws_cli iam delete-role --role-name "$role_name"
done

for user_name in $USER_NAMES; do
  key_ids="$(aws_cli iam list-access-keys --user-name "$user_name" --query 'AccessKeyMetadata[].AccessKeyId' --output text)"
  for key_id in $key_ids; do
    aws_cli iam delete-access-key --user-name "$user_name" --access-key-id "$key_id"
  done
  policy_names="$(aws_cli iam list-user-policies --user-name "$user_name" --query 'PolicyNames[]' --output text)"
  for policy_name in $policy_names; do
    aws_cli iam delete-user-policy --user-name "$user_name" --policy-name "$policy_name"
  done
  aws_cli iam delete-user --user-name "$user_name"
done
