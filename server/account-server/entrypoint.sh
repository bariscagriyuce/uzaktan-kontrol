#!/bin/sh
# Bind-mounted data directories are created root-owned by Docker; hand the
# database directory to the unprivileged user, then drop root.
set -e
chown -R app:app /data
exec setpriv --reuid=app --regid=app --init-groups "$@"
