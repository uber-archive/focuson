#!/bin/bash

set -ex
set -o pipefail

# Create virtualenv if we need to
if [ "$REBUILD_VIRTUALENV" == "true" ]; then
  rm -rf "$VIRTUALENV"
else
  echo "Leaving virtualenv alone..."
fi

cd scoper
make cron
