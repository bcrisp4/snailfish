#!/usr/bin/env bash
# Smoke test of a relay image: tools/image-smoke-test.sh IMAGE
#
# The verify and publish-image workflows run it on each architecture. The
# container runs with the hardened settings of the README: a read-only root
# file system, no capabilities and no-new-privileges. Port 8080 of the host
# must be free.
set -euo pipefail

image=${1:?usage: tools/image-smoke-test.sh IMAGE}
name=snailfish-smoke-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

# Kubernetes runAsNonRoot can verify a numeric user only.
user=$(docker image inspect -f '{{.Config.User}}' "$image")
if [ "$user" != 65532:65532 ]; then
  echo "FAIL: image user is '$user', not 65532:65532"; exit 1
fi

# The image has no shell.
if docker run --rm --entrypoint /bin/sh "$image" -c true 2>/dev/null; then
  echo "FAIL: the image has /bin/sh"; exit 1
fi

docker run -d --name "$name" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e SNAILFISH_AUTHORITY=localhost:8080 -p 127.0.0.1:8080:8080 "$image" >/dev/null
status=
for _ in $(seq 60); do
  status=$(docker inspect -f '{{.State.Health.Status}}' "$name")
  if [ "$status" = healthy ]; then break; fi
  sleep 1
done
if [ "$status" != healthy ]; then
  docker logs "$name"
  echo "FAIL: health status is '$status' after 60 s"; exit 1
fi
curl -fsS http://127.0.0.1:8080/v1/info | jq -e '.levels == [1]' >/dev/null
docker stop -t 10 "$name" >/dev/null
code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
if [ "$code" != 0 ]; then
  echo "FAIL: exit code $code after SIGTERM"; exit 1
fi

# The relay does not start without an authority. A relay that starts serves
# forever, so the wait has a time limit.
docker rm "$name" >/dev/null
docker run -d --name "$name" "$image" >/dev/null
if ! code=$(timeout 30 docker wait "$name"); then
  echo "FAIL: the relay started without SNAILFISH_AUTHORITY"; exit 1
fi
if [ "$code" = 0 ]; then
  echo "FAIL: the relay exited 0 without SNAILFISH_AUTHORITY"; exit 1
fi
echo "PASS: $image"
