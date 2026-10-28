#!/usr/bin/env bash
# Короткие сообщения коммитов и публикация первых двух
set -uo pipefail

REPO="/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher"
cd "$REPO" || exit 1

rm -rf _backup_src
rm -f scripts/build_history.sh scripts/rebuild_history.sh scripts/push_first.sh \
      scripts/trim_comments.py scripts/git_setup.sh scripts/git_cleanup.sh \
      scripts/git_secrets.sh scripts/git_reports.sh

rm -rf .git
git init -q -b main
git config core.fileMode false
git config core.autocrlf false
git config core.quotepath false
git config user.name "Ryukotowo"
git config user.email "Ryukotowo@users.noreply.github.com"

stage() { for p in "$@"; do [ -e "$p" ] && git add -- "$p"; done; }

save() {
  local message="$1"; shift
  stage "$@"
  git diff --cached --quiet && return
  git commit -q -m "$message"
  printf '%-34s %s\n' "$message" "$(git rev-parse --short HEAD)"
}

save "структура проекта" pyproject.toml requirements.txt requirements-dev.txt requirements-ml.txt \
  Makefile Dockerfile docker-compose.yml .env.example .gitignore README.md
save "модели" src/siem_enricher/models
save "конфиг" src/siem_enricher/config.py config
save "извлекатель" src/siem_enricher/extractor
save "классификатор" src/siem_enricher/ml
save "происхождение" src/siem_enricher/provenance
save "политики" src/siem_enricher/policy
save "коннекторы" src/siem_enricher/connectors
save "конвейер, cli, http" src/siem_enricher/enricher src/siem_enricher/service src/siem_enricher/*.py
save "тесты" tests
save "скрипты замеров" tools
save "правила и стенд" rules scripts deploy
save "доки" docs
save "отчёты" var

git add -A 2>/dev/null
git diff --cached --quiet || git commit -q -m "мелочи"

echo
echo "=== история ==="
git log --oneline --reverse
echo
echo "файлов: $(git ls-files | wc -l), не закоммичено: $(git status --porcelain | wc -l)"

: "${GIT_TOKEN:?нужен GIT_TOKEN}"
AUTH=$(printf 'x-access-token:%s' "$GIT_TOKEN" | base64 -w0)
git remote remove origin 2>/dev/null
git remote add origin https://github.com/Ryukotowo/siem-enricher.git

SECOND=$(git rev-list --reverse HEAD | sed -n '2p')
echo
echo "публикую по: $(git log -1 --pretty=format:'%h %s' "$SECOND")"
git -c http.extraheader="AUTHORIZATION: basic $AUTH" \
    push --force origin "$SECOND:refs/heads/main" 2>&1 | tail -4
echo
git -c http.extraheader="AUTHORIZATION: basic $AUTH" ls-remote --heads origin 2>&1
