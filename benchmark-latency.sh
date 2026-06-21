#!/bin/bash

# Benchmark event processing latency
# Measures time from "Intercepted" to "Enforcement" decision
# Usage: ./benchmark-latency.sh [number_of_events] [output_file]

NUM_EVENTS=${1:-100}
OUTPUT_FILE=${2:-benchmark_results.txt}

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        QKS Event Processing Latency Benchmark              ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Collecting $NUM_EVENTS events from kernel logs..."
echo ""

# Create a temporary file for calculations
TEMP_FILE=$(mktemp)

# Extract events with their timestamps
sudo journalctl -k --no-pager -n 10000 | grep -E "\[QKS\]" | \
awk '{print $1, $2, $3}' | \
while read DATE TIME ZONE; do
    # Parse kernel logs to find Intercepted and Enforcement
    echo "$DATE $TIME $ZONE"
done > "$TEMP_FILE"

# Parse kernel logs to extract latencies
echo "Processing logs..."
python3 << 'PYTHON_EOF'
import subprocess
import re
from collections import defaultdict
from statistics import mean, stdev

# Get kernel logs with microsecond timestamps from dmesg
result = subprocess.run(['sudo', 'dmesg'], capture_output=True, text=True)

events = defaultdict(dict)
lines = result.stdout.split('\n')

for line in lines:
    if '[QKS]' not in line or 'event_id=' not in line:
        continue
    
    # Extract kernel timestamp: [  700.680803]
    timestamp_match = re.search(r'\[\s*(\d+\.\d+)\]', line)
    if not timestamp_match:
        continue
    
    timestamp = float(timestamp_match.group(1))
    
    # Extract event_id
    eid_match = re.search(r'event_id=(\d+)', line)
    if not eid_match:
        continue
    
    event_id = eid_match.group(1)
    
    # Detect event phase
    if 'Intercepted' in line:
        events[event_id]['intercepted'] = timestamp
    elif 'Enforcement:' in line or 'Verdict decision:' in line:
        events[event_id]['enforcement'] = timestamp

# Calculate latencies
latencies = []
for event_id, phases in events.items():
    if 'intercepted' in phases and 'enforcement' in phases:
        latency_s = phases['enforcement'] - phases['intercepted']
        latency_ms = latency_s * 1000
        if 0 < latency_ms < 1000:  # Filter out anomalies (0 ms likely race condition)
            latencies.append(latency_ms)

if len(latencies) < 5:
    print(f"⚠️  Only {len(latencies)} complete events found.")
    print("Need more kernel activity to benchmark accurately.")
    print("")
    print("Tip: Generate more events with:")
    print("  • Multiple SSH connections")
    print("  • File operations")
    print("  • Network traffic")
    print("  • Process creation")
else:
    latencies.sort()
    
    print(f"✓ Analyzed {len(latencies)} events")
    print("")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║                    LATENCY STATISTICS                      ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print("")
    print(f"  Min Latency:     {min(latencies):.4f} ms")
    print(f"  Max Latency:     {max(latencies):.4f} ms")
    print(f"  Average:         {mean(latencies):.4f} ms")
    if len(latencies) > 1:
        print(f"  Std Deviation:   {stdev(latencies):.4f} ms")
    
    # Calculate percentiles manually
    if len(latencies) >= 4:
        idx_50 = len(latencies) // 2
        idx_90 = int(len(latencies) * 0.9)
        idx_99 = int(len(latencies) * 0.99)
        print(f"  P50:             {latencies[idx_50]:.4f} ms")
        print(f"  P90:             {latencies[idx_90]:.4f} ms")
        if idx_99 < len(latencies):
            print(f"  P99:             {latencies[idx_99]:.4f} ms")
    
    print("")
    print(f"  Sample size:     {len(latencies)} events")
    print("")
    print("  Interpretation:")
    print("    • Kernel space interception + userspace decision + enforcement")
    print("    • Includes Netlink IPC roundtrip + ML-DSA verification")
    print("")

PYTHON_EOF

rm -f "$TEMP_FILE"
