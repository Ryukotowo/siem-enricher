#!/usr/bin/env bash
# Перенос документов ВКР в приватный репозиторий.
set -e

TOKEN="$GIT_TOKEN"
OWNER="Ryukotowo"
PRIVATE_REPO="vkr-docs"
PUBLIC_DIR="/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher"
DOCS="$PUBLIC_DIR/docs/vkr"

echo "--- создаю приватный репозиторий $OWNER/$PRIVATE_REPO ---"
curl -s -o /tmp/repo.json -w '%{http_code}\n' \
  -X POST https://api.github.com/user/repos \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -d "{\"name\":\"$PRIVATE_REPO\",\"private\":true,\"description\":\"Документы ВКР (приватно)\"}"
grep -o '"full_name": *"[^"]*"' /tmp/repo.json | head -1 || true

WORK=$(mktemp -d)
cd "$WORK"
git init -q
git config user.email "Ryukotowo@users.noreply.github.com"
git config user.name "Ryukotowo"
mkdir -p documents
cp -r "$DOCS"/. documents/
git add documents
git commit -q -m "документы ВКР: текст, презентация, тезисы, сводка"
git branch -M main
AUTH=$(printf 'x-access-token:%s' "$TOKEN" | base64 -w0)
git remote add origin "https://github.com/$OWNER/$PRIVATE_REPO.git"
git -c http.extraheader="AUTHORIZATION: basic $AUTH" push -u origin main 2>&1 | tail -2
echo "приватный репозиторий: https://github.com/$OWNER/$PRIVATE_REPO"

echo "--- убираю документы из публичного репозитория ---"
cd "$PUBLIC_DIR"
git rm -r -q --cached docs/vkr
rm -rf docs/vkr
git commit -q -m "документы ВКР перенесены в приватный репозиторий"
git -c http.extraheader="AUTHORIZATION: basic $AUTH" push origin HEAD:refs/heads/main 2>&1 | tail -2
git log --oneline -2
