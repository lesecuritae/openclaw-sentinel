#!/bin/sh
set -eu
base_url="${TEST_BASE_URL:-http://127.0.0.1:18404}"
curl -fsS "$base_url/" >/dev/null
for path in /.env /.git/config /wp-admin /admin; do
  curl -sS -o /dev/null "$base_url$path"
done
for attempt in 1 2 3 4 5; do
  curl -sS -o /dev/null -X POST "$base_url/login?attempt=$attempt"
done
echo "Scanner and login traffic submitted. Use 'docker compose -f docker-compose.test.yml restart testservice' to simulate a restart."
