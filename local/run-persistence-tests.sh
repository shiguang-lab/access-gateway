#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
network="points-local-test-$$"
redis="points-local-redis-test-$$"
postgres="points-local-postgres-test-$$"

cleanup() {
  docker rm -f "$redis" "$postgres" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker network create "$network" >/dev/null
docker run -d --name "$redis" --network "$network" redis:8-alpine redis-server --save '' --appendonly no >/dev/null
docker run -d --name "$postgres" --network "$network" \
  -e POSTGRES_DB=points_test -e POSTGRES_USER=points -e POSTGRES_PASSWORD=local-test-only \
  postgres:18-alpine >/dev/null

for attempt in $(seq 1 30); do
  docker exec "$redis" redis-cli ping >/dev/null 2>&1 && break
  [ "$attempt" -lt 30 ] || exit 1
  sleep 1
done
for attempt in $(seq 1 30); do
  docker exec "$postgres" pg_isready -U points -d points_test >/dev/null 2>&1 && break
  [ "$attempt" -lt 30 ] || exit 1
  sleep 1
done

docker build --target test -f "$root/auth-service/Dockerfile.local" -t auth-service-local-test "$root/auth-service"
docker build --target test -f "$root/points-service/Dockerfile.local" -t points-service-local-test "$root/points-service"

docker run --rm --network "$network" \
  -e AUTH_TEST_REDIS_URL="redis://$redis:6379/0" \
  auth-service-local-test /usr/local/go/bin/go test ./... -count=1

docker run --rm --network "$network" \
  -e POINTS_TEST_DATABASE_URL="postgres://points:local-test-only@$postgres:5432/points_test?sslmode=disable" \
  points-service-local-test /usr/local/go/bin/go test ./... -count=1
