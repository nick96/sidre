#!/usr/bin/env bash
# Run migration.

postgres_service='pg'

# Check postgres is running.
if [ -z "$(docker-compose ps --filter "status=running" --services | grep $postgres_service)" ]
then
    echo "$postgres_service not running. It needs to be up to run sqlx prepare."
    exit 1
fi

docker-compose run --workdir=/workspace/sidre sidre-test sqlx migrate run