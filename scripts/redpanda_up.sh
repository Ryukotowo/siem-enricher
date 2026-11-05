#!/bin/bash
# Подъём Redpanda и создание топика для событий SIEM
set -u
NAME=siem-redpanda
TOPIC=siem-events

docker rm -f $NAME >/dev/null 2>&1
docker run -d --name $NAME -p 9092:9092 -p 9644:9644 \
  redpandadata/redpanda:v24.2.7 \
  redpanda start --overprovisioned --smp 1 --memory 1G --reserve-memory 0M \
  --node-id 0 --check=false \
  --kafka-addr PLAINTEXT://0.0.0.0:9092 \
  --advertise-kafka-addr PLAINTEXT://localhost:9092 >/dev/null 2>&1

for attempt in $(seq 1 20); do
  sleep 2
  if docker exec $NAME rpk cluster health >/dev/null 2>&1; then
    echo "кластер готов"
    break
  fi
done

docker exec $NAME rpk topic create $TOPIC -p 1 -r 1 2>&1 | tail -2
echo "--- топики ---"
docker exec $NAME rpk topic list
echo "--- брокер ---"
docker exec $NAME rpk cluster info 2>&1 | head -6
