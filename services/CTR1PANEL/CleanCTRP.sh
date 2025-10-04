#!/bin/bash

echo "Start clean..."
echo "Clean Application data"

docker compose -f docker compose.yml down
rm -r db
rm -r logs

docker compose -f docker compose.yml up -d
docker compose -f docker compose.yml down
docker compose -f docker compose.yml up -d

echo "Finish clean..."