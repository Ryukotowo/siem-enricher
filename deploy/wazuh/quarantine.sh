#!/bin/sh
# Карантин файла по решению сервиса обогащения

read INPUT_LINE
LOG=/var/ossec/logs/active-responses.log
QUARANTINE=/var/ossec/quarantine
mkdir -p "$QUARANTINE"

echo "$(date '+%Y-%m-%d %H:%M:%S') quarantine: получен вызов" >> "$LOG"

FILE=$(echo "$INPUT_LINE" | sed -n 's/.*"dlp\.file"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
[ -z "$FILE" ] && FILE=$(echo "$INPUT_LINE" | sed -n 's/.*"file"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

if [ -z "$FILE" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') quarantine: файл в событии не найден" >> "$LOG"
  exit 1
fi

NAME=$(basename "$FILE")
if [ -f "$FILE" ]; then
  mv "$FILE" "$QUARANTINE/$NAME"
  chmod 000 "$QUARANTINE/$NAME"
  echo "$(date '+%Y-%m-%d %H:%M:%S') quarantine: перемещён $FILE -> $QUARANTINE/$NAME" >> "$LOG"
else
  echo "$(date '+%Y-%m-%d %H:%M:%S') quarantine: файл отсутствует: $FILE" >> "$LOG"
  exit 1
fi

exit 0
