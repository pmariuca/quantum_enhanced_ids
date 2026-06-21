#!/bin/bash

# Start backend and frontend together in the background

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.services.pid"

echo "================================"
echo "Quantum-Enhanced IDS - Services"
echo "================================"
echo ""

# Check if services are already running
if [ -f "$PID_FILE" ]; then
    echo "Services already running (PID file exists)"
    echo "Stop with: ./stop-services.sh"
    exit 1
fi

echo "Starting Backend (Port 8080) and Frontend (Port 4200)..."
echo ""

# Start backend in background
cd "$SCRIPT_DIR/backend"
echo "🚀 Building Backend..."
go build -o qks_backend main.go
echo "🚀 Starting Backend..."
./qks_backend > "$SCRIPT_DIR/.backend.log" 2>&1 &
BACKEND_PID=$!
echo "   Backend PID: $BACKEND_PID"

# Start frontend in background
cd "$SCRIPT_DIR/pqc-enhanced-ids"
echo "Starting Frontend..."
npm start > "$SCRIPT_DIR/.frontend.log" 2>&1 &
FRONTEND_PID=$!
echo "   Frontend PID: $FRONTEND_PID"

# Save PIDs
echo "$BACKEND_PID" > "$PID_FILE"
echo "$FRONTEND_PID" >> "$PID_FILE"

echo ""
echo "✓ Both services started!"
echo ""
echo "Services running at:"
echo "   Backend:  http://192.168.1.248:8080/api"
echo "   Frontend: http://192.168.1.248:4200"
echo ""
echo "View logs:"
echo "   Backend:  tail -f .backend.log"
echo "   Frontend: tail -f .frontend.log"
echo ""
echo "Stop services:"
echo "   ./stop-services.sh"
