#!/bin/bash
# Заливка событий набора в топик siem-events
set -u
REPO=/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher
cd "$REPO" || exit 1
NAME=siem-redpanda

docker start $NAME >/dev/null 2>&1 || exit 1
for attempt in $(seq 1 20); do
  sleep 2
  docker exec $NAME rpk cluster health >/dev/null 2>&1 && break
done

docker exec $NAME rpk topic create siem-events -p 1 -r 1 >/dev/null 2>&1
docker exec $NAME rpk topic create siem-enriched -p 1 -r 1 >/dev/null 2>&1
docker exec $NAME rpk topic delete siem-events >/dev/null 2>&1
docker exec $NAME rpk topic create siem-events -p 1 -r 1 >/dev/null 2>&1

rm -f var/screens/kafka_enriched.jsonl

echo "событий в наборе: $(wc -l < var/experiment/dataset.jsonl)"
docker exec -i $NAME rpk topic produce siem-events -f '%v\n' < var/experiment/dataset.jsonl 2>&1 | tail -2

echo "--- топики ---"
docker exec $NAME rpk topic list
echo "--- в топике событий ---"
docker exec $NAME rpk topic describe siem-events -s 2>&1 | grep -E 'high_watermark|partition' | head -4
