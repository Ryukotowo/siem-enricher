#!/usr/bin/env bash
# Документы — только в приватный репозиторий; чистим публичный.
set -e

TOKEN="$GIT_TOKEN"
PUBLIC_DIR="/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher"
SRC="/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/vkr"
AUTH=$(printf 'x-access-token:%s' "$TOKEN" | base64 -w0)

echo "--- 1. обновляю приватный репозиторий vkr ---"
WORK=$(mktemp -d)
cd "$WORK"
git clone -q "https://github.com/Ryukotowo/vkr.git" repo
cd repo
git config user.email "Ryukotowo@users.noreply.github.com"
git config user.name "Ryukotowo"
cp "$SRC/ВКР_Иванченко.docx" documents/
cp "$SRC/ВКР_Иванченко_Презентация.pptx" documents/
cp "$SRC/Тезисы_Иванченко.docx" documents/
cp "$SRC/Сводка_для_консультанта.docx" documents/
cp "$SRC/figures/panel_stream.gif" figures/ 2>/dev/null || true
cp "$SRC/figures/panel_settings.png" figures/ 2>/dev/null || true
git add -A
git commit -q -m "документы: настройки эксплуатации, слайд 25, раздел 3.5" || echo "без изменений"
git -c http.extraheader="AUTHORIZATION: basic $AUTH" push origin main 2>&1 | tail -2

echo "--- 2. убираю docs/vkr из публичного репозитория ---"
cd "$PUBLIC_DIR"
git rm -r -q --cached docs/vkr
rm -rf docs/vkr
echo "docs/vkr" >> .gitignore
git add -A
git commit -q -m "документы перенесены в приватный репозиторий vkr"
git -c http.extraheader="AUTHORIZATION: basic $AUTH" push origin HEAD:refs/heads/main 2>&1 | tail -2

echo "--- 3. чищу документы из истории публичного ---"
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f \
  --index-filter 'git rm -r --cached --ignore-unmatch docs/vkr' \
  --prune-empty -- --all 2>&1 | tail -2
rm -rf .git/refs/original
git reflog expire --expire=now --all
git gc --prune=now --quiet
echo "коммитов с docs/vkr: $(git log --oneline --all -- docs/vkr | wc -l)"
git -c http.extraheader="AUTHORIZATION: basic $AUTH" push --force origin main 2>&1 | tail -2
git log --oneline -3
