#!/bin/sh
set -eu

compose_file="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/compose.yaml"
action="${1:-e2e}"

up() {
  docker compose -f "$compose_file" up --build -d
}

down() {
  docker compose -f "$compose_file" down --volumes --remove-orphans
}

smoke() {
  node "$(dirname -- "$compose_file")/smoke.mjs"
}

case "$action" in
  up) up ;;
  smoke) smoke ;;
  down) down ;;
  e2e)
    trap down EXIT INT TERM
    down
    up
    smoke
    ;;
  *)
    echo "usage: $0 {up|smoke|down|e2e}" >&2
    exit 2
    ;;
esac
