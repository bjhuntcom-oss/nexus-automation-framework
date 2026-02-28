#!/bin/bash
# Nexus Automation Framework — Docker Entrypoint
# Ensures knowledge.db is always a proper SQLite file, never a directory.
set -e

DB_PATH="${NEXUS_DB_PATH:-/app/knowledge.db}"

# Docker creates a directory when the host file doesn't exist at mount time.
# Detect and remove it so SQLite can create a proper file.
if [ -d "$DB_PATH" ]; then
    echo "[entrypoint] WARNING: $DB_PATH is a directory (host file missing at mount time)."
    echo "[entrypoint] Removing spurious directory — a fresh SQLite DB will be created."
    rm -rf "$DB_PATH"
fi

# Ensure parent directory exists (safety net)
mkdir -p "$(dirname "$DB_PATH")"

if [ -f "$DB_PATH" ]; then
    SIZE=$(du -sh "$DB_PATH" 2>/dev/null | cut -f1)
    echo "[entrypoint] knowledge.db found: $SIZE"
else
    echo "[entrypoint] knowledge.db not mounted — fresh DB will be initialised at startup."
fi

exec "$@"
