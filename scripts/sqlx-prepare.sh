#!/usr/bin/env bash
# Rebuild sqlx-data.json. This requires the postgres instance to be running.

postgres_service='pg'

# Check postgres is running.
if [ -z "$(docker-compose ps -q $postgres_service)" ]
then
    echo "$postgres_service not running. It needs to be up to run sqlx prepare."
    exit 1
fi

# Rebuild sqlx-data.json. As we're using workspaces the command is a bit weird. We
# need to move into the the sidre directory but still pass the bin name to rustc.
# There's an issue tracking this: https://github.com/launchbadge/sqlx/issues/353.
docker-compose run --workdir=/workspace/sidre sidre-test cargo +nightly sqlx prepare -- --bin sidre
