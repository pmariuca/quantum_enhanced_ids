#!/bin/bash

# Stop backend and frontend services

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.services.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "No services running (PID file not found)"
    exit 0
fi

echo "Stopping services..."

# Read PIDs and kill them
while IFS= read -r PID; do
    if [ -n "$PID" ]; then
        if ps -p "$PID" > /dev/null 2>&1; then
            echo "  Killing PID $PID..."
            kill "$PID" 2>/dev/null || true
            sleep 1
            # Force kill if still running
            if ps -p "$PID" > /dev/null 2>&1; then
                kill -9 "$PID" 2>/dev/null || true
            fi
        fi
    fi
done < "$PID_FILE"

rm -f "$PID_FILE"

echo "✓ Services stopped"
echo ""
echo "View logs if needed:"
echo "   tail -f .backend.log"
echo "   tail -f .frontend.log"
