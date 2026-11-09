#!/usr/bin/env bash
# Разбор URL-параметров Quickwit UI.
set -e
BASE=http://localhost:7280
echo "--- html ---"
curl -s "$BASE/ui/" | grep -o 'src="[^"]*"' | head -5
BUNDLE=$(curl -s "$BASE/ui/" | grep -o 'src="[^"]*\.js"' | head -1 | sed 's/src="//; s/"//')
echo "bundle: $BUNDLE"
echo "--- параметры поиска в бандле ---"
curl -s "$BASE$BUNDLE" | grep -o 'indexId[^,;)]\{0,60\}' | head -8
echo "--- альтернативы ---"
curl -s "$BASE$BUNDLE" | grep -o '"index[a-zA-Z]*"' | sort -u | head -10
