#!/bin/sh
# Container entrypoint: apply pending migrations, then start the API.
set -e
cd /app/apps/api
node node_modules/prisma/build/index.js migrate deploy
exec node --enable-source-maps dist/main.js
