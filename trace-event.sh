#!/bin/bash

# Trace a specific event ID across all system components
# Usage: ./trace-event.sh <event_id>

if [ -z "$1" ]; then
    echo "Usage: ./trace-event.sh <event_id>"
    echo "Example: ./trace-event.sh 2795"
    exit 1
fi

EVENT_ID="$1"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║          Tracing Event ID: $EVENT_ID"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "DAEMON LOGS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
sudo journalctl -u qks-daemon -e | grep -A 5 "id=$EVENT_ID" | head -20

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "KERNEL LOGS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
sudo journalctl -k | grep "id=$EVENT_ID"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "EVENT STORE (events.jsonl)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
grep "event_id\":$EVENT_ID" /opt/qks/policy/events.jsonl | python3 -m json.tool 2>/dev/null || grep "event_id\":$EVENT_ID" /opt/qks/policy/events.jsonl

echo ""
echo "✓ Trace complete for event ID: $EVENT_ID"
