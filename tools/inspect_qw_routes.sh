#!/usr/bin/env bash
# Поиск маршрутов и параметров Quickwit UI в бандле.
set -e
BASE=http://localhost:7280
BUNDLE=$(curl -s "$BASE/ui/" | grep -o 'src="[^"]*\.js"' | head -1 | sed 's/src="//; s/"//')
echo "bundle: $BUNDLE"
curl -s "$BASE$BUNDLE" -o /tmp/qw_bundle.js
echo "размер: $(wc -c < /tmp/qw_bundle.js) байт"
echo "--- маршруты ---"
grep -o 'path:"[^"]*"' /tmp/qw_bundle.js | sort -u | head -20
echo "--- как читается indexId ---"
grep -o '.\{60\}indexId.\{60\}' /tmp/qw_bundle.js | head -6
