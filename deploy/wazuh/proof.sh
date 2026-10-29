#!/bin/sh
echo "=== журнал активного реагирования ==="
tail -3 /var/ossec/logs/active-responses.log
echo
echo "=== каталог карантина ==="
ls -l /var/ossec/quarantine
echo
echo "=== исходный файл ==="
ls -l /tmp/secret.txt 2>&1 || echo "файл отсутствует: перемещён в карантин"
