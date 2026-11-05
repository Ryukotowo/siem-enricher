#!/usr/bin/env bash
# Удаление документов ВКР из истории публичного репозитория.
set -e

TOKEN="$GIT_TOKEN"
PUBLIC_DIR="/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher"

cd "$PUBLIC_DIR"
AUTH=$(printf 'x-access-token:%s' "$TOKEN" | base64 -w0)

echo "--- до чистки (файлы docs/vkr в истории) ---"
git log --oneline --all -- docs/vkr | head -5
COUNT=$(git log --oneline --all -- docs/vkr | wc -l)
echo "коммитов с документами: $COUNT"

echo "--- переписываю историю ---"
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f \
  --index-filter 'git rm -r --cached --ignore-unmatch docs/vkr' \
  --prune-empty -- --all 2>&1 | tail -3

rm -rf .git/refs/original
git reflog expire --expire=now --all
git gc --prune=now --quiet

echo "--- после чистки ---"
echo "коммитов с документами: $(git log --oneline --all -- docs/vkr | wc -l)"
git log --oneline -3

echo "--- публикую ---"
git -c http.extraheader="AUTHORIZATION: basic $AUTH" push --force origin main 2>&1 | tail -2
