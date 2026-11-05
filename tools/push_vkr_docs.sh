#!/usr/bin/env bash
# Публикация документов ВКР в репозиторий Ryukotowo/vkr.
set -e

TOKEN="$GIT_TOKEN"
REPO="https://github.com/Ryukotowo/vkr.git"
SRC="/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/vkr"

echo "--- проверяю видимость репозитория ---"
curl -s -H "Authorization: Bearer $TOKEN" https://api.github.com/repos/Ryukotowo/vkr \
  | grep -o '"private": *[a-z]*' | head -1

WORK=$(mktemp -d)
cd "$WORK"
git init -q
git config user.email "Ryukotowo@users.noreply.github.com"
git config user.name "Ryukotowo"

mkdir -p documents figures
cp "$SRC/ВКР_Иванченко.docx" documents/
cp "$SRC/ВКР_Иванченко_Презентация.pptx" documents/
cp "$SRC/Тезисы_Иванченко.docx" documents/
cp "$SRC/Сводка_для_консультанта.docx" documents/
cp "$SRC/figures/panel_stream.gif" figures/ 2>/dev/null || true

cat > README.md <<'EOF'
# Документы ВКР

Иванченко Даниил Вадимович, гр. 1363.
«Программное средство предотвращения утечки информации в информационных системах
на основе моделей и методов искусственного интеллекта».

- `documents/ВКР_Иванченко.docx` — пояснительная записка, 76 страниц
- `documents/ВКР_Иванченко_Презентация.pptx` — презентация, 25 слайдов
- `documents/Тезисы_Иванченко.docx` — тезисы для апробации
- `documents/Сводка_для_консультанта.docx` — сводка по работе
- `figures/panel_stream.gif` — анимация работы панели

Код сервиса: приватность работ по ВКР; репозиторий с кодом —
[siem-enricher](https://github.com/Ryukotowo/siem-enricher).
EOF

git add -A
git commit -q -m "документы ВКР: пояснительная записка, презентация, тезисы, сводка"
git branch -M main
AUTH=$(printf 'x-access-token:%s' "$TOKEN" | base64 -w0)
git remote add origin "$REPO"
git -c http.extraheader="AUTHORIZATION: basic $AUTH" push -u origin main --force 2>&1 | tail -2
echo "готово: https://github.com/Ryukotowo/vkr"
