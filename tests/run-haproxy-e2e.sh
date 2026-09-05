#!/bin/sh
set -eu

compose="docker compose -f docker-compose.test.yml"
trap '$compose --profile e2e down -v --remove-orphans' EXIT INT TERM
$compose --profile e2e down -v --remove-orphans >/dev/null 2>&1 || true
$compose --profile e2e up -d --build sentinel testservice haproxy
$compose --profile e2e run --rm test-client
