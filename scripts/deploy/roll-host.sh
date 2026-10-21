#!/usr/bin/env bash
# roll-host.sh <version> — switch the production host to exactly <version>
# through SSM (the host's /opt/qeet-id/redeploy.sh, qeet-id-deploy), then
# confirm GET /version serves it. Used by .github/workflows/deploy.yml for both
# a release and a rollback; runs on the CI runner with AWS credentials.
#
# Env: SSM_PREFIX (e.g. /qeet-id/prod), API_URL (e.g. https://api.id.qeet.in),
#      ECR_REPOSITORY_URL (<account>.dkr.ecr.<region>.amazonaws.com/<name>).
#
# Fails, before touching the host, when <version> isn't a release tag or a
# commit sha, or its image is no longer in ECR. redeploy.sh itself refuses a
# version whose build can't run on the current schema, and fails when it can't
# record the version it replaces; either fails this job.
set -euo pipefail

version="${1:?usage: roll-host.sh <version>}"
if ! [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ || $version =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::'$version' is not a release tag (vX.Y.Z) or a full commit sha"
  exit 1
fi
: "${SSM_PREFIX:?}" "${API_URL:?}" "${ECR_REPOSITORY_URL:?}"

repo_name="${ECR_REPOSITORY_URL#*/}"
if ! aws ecr describe-images --repository-name "$repo_name" --image-ids "imageTag=$version" > /dev/null 2>&1; then
  echo "::error::$version is not in ECR ($repo_name): it was never pushed or is no longer retained. Production is untouched."
  exit 1
fi

instance_id=$(aws ssm get-parameter --name "$SSM_PREFIX/INSTANCE_ID" --query Parameter.Value --output text)
echo "Switching $instance_id to $version"
cmd_id=$(aws ssm send-command \
  --instance-ids "$instance_id" \
  --document-name AWS-RunShellScript \
  --comment "redeploy $version" \
  --parameters "commands=[\"/opt/qeet-id/redeploy.sh $version\"]" \
  --query Command.CommandId --output text)
echo "SSM command: $cmd_id"
aws ssm wait command-executed --command-id "$cmd_id" --instance-id "$instance_id" || true
invocation() {
  aws ssm get-command-invocation --command-id "$cmd_id" --instance-id "$instance_id" --query "$1" --output text
}
status=$(invocation Status)
echo "----- stdout -----"
invocation StandardOutputContent
echo "----- stderr -----"
invocation StandardErrorContent
echo "status: $status"
if [ "$status" != "Success" ]; then
  echo "::error::redeploy.sh $version failed on the host (see its output above)"
  exit 1
fi

# The host reports what it serves; confirm from outside too.
for _ in $(seq 1 30); do
  serving=$(curl -fsS "$API_URL/version" | jq -r '.version // empty' || true)
  if [ "$serving" = "$version" ]; then
    curl -fsS "$API_URL/version" | jq -c .
    exit 0
  fi
  sleep 5
done
echo "::error::$API_URL/version reports '${serving:-nothing}', want $version"
exit 1
