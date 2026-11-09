#!/usr/bin/env bash
# Документы — только в приватный репозиторий; из публичного убираем полностью.
set -e
export GIT_TERMINAL_PROMPT=0

TOKEN="$GIT_TOKEN"
PUBLIC_DIR="/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher"
SRC="/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/vkr"
AUTH=$(printf 'x-access-token:%s' "$TOKEN" | base64 -w0)
HEADER="AUTHORIZATION: basic $AUTH"

echo "=== 1. приватный репозиторий vkr ==="
WORK=$(mktemp -d)
cd "$WORK"
git -c http.extraheader="$HEADER" clone -q https://github.com/Ryukotowo/vkr.git repo
cd repo
git config user.email "Ryukotowo@users.noreply.github.com"
git config user.name "Ryukotowo"
mkdir -p documents figures
cp "$SRC/ВКР_Иванченко.docx" documents/
cp "$SRC/ВКР_Иванченко_Презентация.pptx" documents/
cp "$SRC/Тезисы_Иванченко.docx" documents/
cp "$SRC/Сводка_для_консультанта.docx" documents/
cp "$SRC/figures/panel_stream.gif" figures/ 2>/dev/null || true
cp "$SRC/figures/panel_settings.png" figures/ 2>/dev/null || true
git add -A
if git diff --cached --quiet; then
  echo "изменений нет"
else
  git commit -q -m "документы: настройки эксплуатации (слайд 25, раздел 3.5)"
fi
git -c http.extraheader="$HEADER" push origin main 2>&1 | tail -2

echo "=== 2. публичный репозиторий: удаляю docs/vkr ==="
cd "$PUBLIC_DIR"
echo "в HEAD сейчас:"
git ls-tree -r --name-only HEAD -- docs/vkr | head -5 || true
git rm -r -q --cached docs/vkr 2>/dev/null || true
rm -rf docs/vkr
grep -qxF "docs/vkr/" .gitignore 2>/dev/null || echo "docs/vkr/" >> .gitignore
git add -A
git commit -q -m "документы ведутся в приватном репозитории vkr" || echo "нечего коммитить"

echo "=== 3. чищу историю публичного репозитория ==="
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f \
  --index-filter 'git rm -r --cached --ignore-unmatch docs/vkr' \
  --prune-empty -- --all > /dev/null 2>&1
rm -rf .git/refs/original
git reflog expire --expire=now --all
git gc --prune=now --quiet
echo "коммитов с docs/vkr после чистки: $(git log --oneline --all -- docs/vkr | wc -l)"
git -c http.extraheader="$HEADER" push --force origin main 2>&1 | tail -2
git log --oneline -3
echo "=== готово ==="
