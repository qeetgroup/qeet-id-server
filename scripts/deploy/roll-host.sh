#!/usr/bin/env bash
# roll-host.sh <version> [--roll-back-on-failure] — switch the production host
# to exactly <version> through SSM (the host's /opt/qeet-id/redeploy.sh,
# qeet-id-deploy), then confirm GET /version serves it and GET /readyz is ready.
# Used by .github/workflows/deploy.yml for both a release and a rollback; runs
# on the CI runner with AWS credentials.
#
# Env: SSM_PREFIX (e.g. /qeet-id/prod), API_URL (e.g. https://api.id.qeet.in),
#      ECR_REPOSITORY_URL (<account>.dkr.ecr.<region>.amazonaws.com/<name>),
#      READY_WAIT_SECONDS (default 300).
#
# Fails, before touching the host, when <version> isn't a release tag or a
# commit sha, or its image is no longer in ECR. redeploy.sh itself refuses a
# version whose build can't run on the current schema, and fails when it can't
# record the version it replaces; either fails this job.
#
# With --roll-back-on-failure, a version not ready in time is rolled back to the
# release served before, and the job still fails. The host refuses unsigned
# images, so a version promoted before signing can't be rolled back to.
set -euo pipefail

version="${1:?usage: roll-host.sh <version> [--roll-back-on-failure]}"
roll_back=""
case "${2:-}" in
  "") ;;
  --roll-back-on-failure) roll_back=1 ;;
  *)
    echo "::error::unknown option '$2' (usage: roll-host.sh <version> [--roll-back-on-failure])"
    exit 1
    ;;
esac
release_tag='^v[0-9]+\.[0-9]+\.[0-9]+$'
if ! [[ $version =~ $release_tag || $version =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::'$version' is not a release tag (vX.Y.Z) or a full commit sha"
  exit 1
fi
: "${SSM_PREFIX:?}" "${API_URL:?}" "${ECR_REPOSITORY_URL:?}"
ready_wait="${READY_WAIT_SECONDS:-300}"

repo_name="${ECR_REPOSITORY_URL#*/}"
if ! aws ecr describe-images --repository-name "$repo_name" --image-ids "imageTag=$version" > /dev/null 2>&1; then
  echo "::error::$version is not in ECR ($repo_name): it was never pushed or is no longer retained. Production is untouched."
  exit 1
fi

served() {
  curl -fsS --max-time 10 "$API_URL/version" 2> /dev/null | jq -r ".$1 // empty" 2> /dev/null || true
}

ready() {
  curl -fsS --max-time 10 -o /dev/null "$API_URL/readyz" 2> /dev/null
}

# release_of <version>: the release /version reports for it. A commit sha tag
# is main's merge commit, not the commit the binary reports, so it is resolved
# to the release tag on the same image.
release_of() {
  if [[ $1 =~ $release_tag ]]; then
    echo "$1"
    return
  fi
  aws ecr describe-images --repository-name "$repo_name" --image-ids "imageTag=$1" \
    --query 'imageDetails[0].imageTags' --output json 2> /dev/null |
    jq -r '[.[] | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))][0] // empty' 2> /dev/null || true
}

switch() {
  local target=$1 instance_id cmd_id status
  instance_id=$(aws ssm get-parameter --name "$SSM_PREFIX/INSTANCE_ID" --query Parameter.Value --output text) || return 1
  echo "Switching $instance_id to $target"
  cmd_id=$(aws ssm send-command \
    --instance-ids "$instance_id" \
    --document-name AWS-RunShellScript \
    --comment "redeploy $target" \
    --parameters "commands=[\"/opt/qeet-id/redeploy.sh $target\"]" \
    --query Command.CommandId --output text) || return 1
  echo "SSM command: $cmd_id"
  invocation() {
    aws ssm get-command-invocation --command-id "$cmd_id" --instance-id "$instance_id" --query "$1" --output text
  }
  # Wait up to 10 minutes for redeploy.sh: it pulls, stops the running server
  # (up to its stop grace period, 45s) and waits up to 2 minutes for health,
  # longer than `aws ssm wait command-executed` waits (100s).
  status=Pending
  for _ in $(seq 1 120); do
    status=$(invocation Status 2> /dev/null || echo Pending)
    case "$status" in
      Pending | InProgress | Delayed) sleep 5 ;;
      *) break ;;
    esac
  done
  echo "----- stdout -----"
  invocation StandardOutputContent || true
  echo "----- stderr -----"
  invocation StandardErrorContent || true
  echo "status: $status"
  if [ "$status" != "Success" ]; then
    echo "::error::redeploy.sh $target failed on the host (see its output above)"
    return 1
  fi
}

await() {
  local target=$1 want waited=0 serving=""
  want=$(release_of "$target")
  while [ "$waited" -le "$ready_wait" ]; do
    if [ -n "$want" ]; then
      serving=$(served version)
    else
      serving=$(served commit)
    fi
    if [ "$serving" = "${want:-$target}" ] && ready; then
      curl -fsS --max-time 10 "$API_URL/version" | jq -c .
      return 0
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo "::error::$API_URL is not ready serving $target after ${ready_wait}s: /version reports '${serving:-nothing}', want ${want:-$target}"
  return 1
}

previous=$(served version)
[[ $previous =~ $release_tag ]] || previous=""

if switch "$version" && await "$version"; then
  exit 0
fi
if [ -z "$roll_back" ]; then
  exit 1
fi
if [ -z "$previous" ] || [ "$previous" = "$(release_of "$version")" ]; then
  echo "::error::$version failed and no earlier release was serving before it, so there is nothing to roll back to. Production needs attention (the Deployment Runbook in qeet-id-files/05-engineering/operations.md)."
  exit 1
fi
# redeploy.sh refuses some versions before switching: nothing to roll back.
if [ "$(served version)" = "$previous" ] && ready; then
  echo "::error::$version was not deployed; $previous is still serving and ready. Nothing to roll back."
  exit 1
fi
echo "::warning::$version is not healthy: rolling production back to $previous"
if switch "$previous" && await "$previous"; then
  echo "::error::$version failed its deploy and production was rolled back to $previous, which is serving and ready. $version is not released."
  exit 1
fi
echo "::error::$version failed its deploy, and rolling back to $previous failed too (for example, a build from before a migration this one applied can't run on the schema). Production needs attention: restore or roll forward (the Deployment Runbook in qeet-id-files/05-engineering/operations.md)."
exit 1
