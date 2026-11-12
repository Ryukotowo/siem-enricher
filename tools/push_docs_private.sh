#!/usr/bin/env bash
# Обновление приватного репозитория документов.
set -e
export GIT_TERMINAL_PROMPT=0

TOKEN="$GIT_TOKEN"
SRC="/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/vkr"
AUTH=$(printf 'x-access-token:%s' "$TOKEN" | base64 -w0)
HEADER="AUTHORIZATION: basic $AUTH"

WORK=$(mktemp -d)
cd "$WORK"
git -c http.extraheader="$HEADER" clone -q https://github.com/Ryukotowo/vkr.git repo
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
if git diff --cached --quiet; then
  echo "изменений нет"
else
  git commit -q -m "документы: производительность 460 событий/с, 152 теста"
fi
git -c http.extraheader="$HEADER" push origin main 2>&1 | tail -2
