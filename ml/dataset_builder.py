"""
Dataset builder helper
Parse events.jsonl, windows events, extract features, and export train/val/test CSVs.

Usage:
    python dataset_builder.py --input ../input_data --output ./data
    python dataset_builder.py --input ../input_data/events.jsonl --output ./data --window-size 5.0
"""

import json
import argparse
import os
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Set
import csv

from schema import (
    WINDOW_SIZE_SEC,
    FALLBACK_KEY,
    EventType,
    SyscallSubtype,
    SUSPICIOUS_PORTS,
    SYSCALL_FEATURES,
    NETWORK_FEATURES,
    METADATA_COLUMNS,
    ALL_COLUMNS,
    Label,
    POLICY_TO_LABEL,
    RawEvent,
    WindowSample,
    compute_window_id,
    window_id_to_timestamp,
    is_suspicious_port,
    get_grouping_key,
    validate_sample,
)

def parse_event(line: str) -> Optional[RawEvent]:
    # parse a single JSONL line into a RawEvent.
    try:
        data = json.loads(line.strip())
    except json.JSONDecodeError:
        return None
    
    event = RawEvent(
        ts_daemon=data.get("ts_daemon", ""),
        event_id=data.get("event_id", 0),
        event_type=data.get("type", ""),
        policy=data.get("policy", "UNKNOWN"),
        reason=data.get("reason", ""),
    )
    
    # parse type-specific fields
    if event.event_type == "EXEC":
        exec_data = data.get("exec", {})
        event.pid = exec_data.get("pid")
        event.ppid = exec_data.get("ppid")
        event.uid = exec_data.get("uid")
        event.exec_path = exec_data.get("path")
    
    elif event.event_type == "SYSCALL":
        sc_data = data.get("syscall", {})
        event.pid = sc_data.get("pid")
        event.ppid = sc_data.get("ppid")
        event.uid = sc_data.get("uid")
        event.exec_path = sc_data.get("exec_path")
        event.sc_nr = sc_data.get("nr")
        event.sc_subtype = sc_data.get("subtype")
        event.sc_flags = sc_data.get("flags")
        event.sc_prot = sc_data.get("prot")
    
    elif event.event_type == "PACKET":
        pkt_data = data.get("packet", {})
        event.pid = pkt_data.get("pid")
        event.uid = pkt_data.get("uid")
        event.exec_path = pkt_data.get("exec_path")
        event.src_ip = pkt_data.get("src_ip")
        event.dst_ip = pkt_data.get("dst_ip")
        event.src_port = pkt_data.get("src_port")
        event.dst_port = pkt_data.get("dst_port")
        event.protocol = pkt_data.get("protocol")
        event.packet_len = pkt_data.get("len")
    
    elif event.event_type == "PACKET_IN":
        pkt_data = data.get("packet_in", {})
        # PACKET_IN has no process context
        event.src_ip = pkt_data.get("src_ip")
        event.dst_ip = pkt_data.get("dst_ip")
        event.src_port = pkt_data.get("src_port")
        event.dst_port = pkt_data.get("dst_port")
        event.protocol = pkt_data.get("protocol")
        event.packet_len = pkt_data.get("len")
        event.tcp_flags = pkt_data.get("tcp_flags")
    
    elif event.event_type == "DNS":
        dns_data = data.get("dns", {})
        event.pid = dns_data.get("pid")
        event.uid = dns_data.get("uid")
        event.exec_path = dns_data.get("exec_path")
        event.src_ip = dns_data.get("src_ip")
        event.dst_ip = dns_data.get("dst_ip")
        event.qname = dns_data.get("qname")
        event.qtype = dns_data.get("qtype")
    
    return event


def load_events(jsonl_path: str) -> List[RawEvent]:
    # load all events from a JSONL file
    events = []
    parse_errors = 0
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            event = parse_event(line)
            if event is None:
                parse_errors += 1
                print(f"  Warning: Failed to parse line {line_num}")
            else:
                events.append(event)
    
    print(f"  Loaded {len(events)} events ({parse_errors} parse errors)")
    return events


class WindowAggregator:
    # aggregate events into windows and computes features
    
    def __init__(self, window_size_sec: float = WINDOW_SIZE_SEC):
        self.window_size_sec = window_size_sec
        # key: (window_id, exec_path)
        # value: dict with running aggregations
        self.windows: Dict[Tuple[int, str], Dict] = defaultdict(self._init_window)
    
    def _init_window(self) -> Dict:
        # initialize a new window aggregation dict
        return {
            "events": [],
            "policies": [],
            # Syscall counters
            "sc_exec_count": 0,
            "sc_memfd_count": 0,
            "sc_mprotect_x_count": 0,
            "sc_mmap_x_count": 0,
            "sc_priv_change_count": 0,
            "sc_clone_count": 0,
            "sc_namespace_count": 0,
            "sc_socket_create_count": 0,
            # Network accumulators
            "net_packet_out_count": 0,
            "net_packet_in_count": 0,
            "net_dns_count": 0,
            "net_suspicious_port_hits": 0,
            "dst_ips": set(),
            "dst_ports": set(),
            "packet_lens": [],
            "tcp_flags_seen": [],
        }
    
    def add_event(self, event: RawEvent) -> None:
        # add an event to its corresponding window
        if not event.ts_daemon:
            return
        
        window_id = compute_window_id(event.ts_daemon, self.window_size_sec)
        grouping_key = get_grouping_key(event)
        key = (window_id, grouping_key)
        
        w = self.windows[key]
        w["events"].append(event)
        w["policies"].append(event.policy)
        
        # update counters based on event type
        if event.event_type == "EXEC":
            w["sc_exec_count"] += 1
        
        elif event.event_type == "SYSCALL":
            subtype = event.sc_subtype
            if subtype == SyscallSubtype.MEMFD_CREATE:
                w["sc_memfd_count"] += 1
            elif subtype == SyscallSubtype.MPROTECT_X:
                w["sc_mprotect_x_count"] += 1
            elif subtype == SyscallSubtype.MMAP_X:
                w["sc_mmap_x_count"] += 1
            elif subtype == SyscallSubtype.PRIV_CHANGE:
                w["sc_priv_change_count"] += 1
            elif subtype == SyscallSubtype.CLONE_FAMILY:
                w["sc_clone_count"] += 1
            elif subtype == SyscallSubtype.UNSHARE:
                w["sc_namespace_count"] += 1
            elif subtype == SyscallSubtype.SETNS:
                w["sc_namespace_count"] += 1
            elif subtype == SyscallSubtype.SOCKET_CREATE:
                w["sc_socket_create_count"] += 1
        
        elif event.event_type == "PACKET":
            w["net_packet_out_count"] += 1
            if event.dst_ip:
                w["dst_ips"].add(event.dst_ip)
            if event.dst_port:
                w["dst_ports"].add(event.dst_port)
                if is_suspicious_port(event.dst_port):
                    w["net_suspicious_port_hits"] += 1
            if event.packet_len:
                w["packet_lens"].append(event.packet_len)
        
        elif event.event_type == "PACKET_IN":
            w["net_packet_in_count"] += 1
            if event.src_ip:
                w["dst_ips"].add(event.src_ip)  # For incoming, track source
            if event.src_port:
                w["dst_ports"].add(event.src_port)
                if is_suspicious_port(event.src_port):
                    w["net_suspicious_port_hits"] += 1
            if event.packet_len:
                w["packet_lens"].append(event.packet_len)
            if event.tcp_flags:
                w["tcp_flags_seen"].append(event.tcp_flags)
        
        elif event.event_type == "DNS":
            w["net_dns_count"] += 1
    
    def compute_label(self, policies: List[str]) -> int:
        """
        compute label for a window based on policies of its events
        
        strategy: if ANY event is DENY, label = MALICIOUS
                  if all are ALLOW, label = BENIGN
                  if any UNKNOWN and no DENY, label = UNLABELED
        """
        has_deny = any(p == "DENY" for p in policies)
        has_unknown = any(p == "UNKNOWN" for p in policies)
        
        if has_deny:
            return Label.MALICIOUS
        elif has_unknown:
            return Label.UNLABELED
        else:
            return Label.BENIGN
    
    def compute_tcp_flags_anomaly(self, flags_list: List[str]) -> float:
        # compute anomaly ratio for TCP flags
        if not flags_list:
            return 0.0
        
        normal_flags = {"0x02", "0x12", "0x10", "0x18", "0x11", "0x14"}
        anomalous = sum(1 for f in flags_list if f not in normal_flags)
        return anomalous / len(flags_list)
    
    def finalize(self, source: str = "local") -> List[WindowSample]:
        # convert all windows to WindowSample objects
        samples = []
        
        for (window_id, exec_path), w in self.windows.items():
            # compute derived features
            mean_packet_len = 0.0
            if w["packet_lens"]:
                mean_packet_len = sum(w["packet_lens"]) / len(w["packet_lens"])
            
            tcp_anomaly = self.compute_tcp_flags_anomaly(w["tcp_flags_seen"])
            label = self.compute_label(w["policies"])
            
            sample = WindowSample(
                window_id=window_id,
                exec_path=exec_path,
                window_start=window_id_to_timestamp(window_id, self.window_size_sec),
                event_count=len(w["events"]),
                source=source,
                # Syscall features
                sc_exec_count=w["sc_exec_count"],
                sc_memfd_count=w["sc_memfd_count"],
                sc_mprotect_x_count=w["sc_mprotect_x_count"],
                sc_mmap_x_count=w["sc_mmap_x_count"],
                sc_priv_change_count=w["sc_priv_change_count"],
                sc_clone_count=w["sc_clone_count"],
                sc_namespace_count=w["sc_namespace_count"],
                sc_socket_create_count=w["sc_socket_create_count"],
                # Network features
                net_packet_out_count=w["net_packet_out_count"],
                net_packet_in_count=w["net_packet_in_count"],
                net_dns_count=w["net_dns_count"],
                net_suspicious_port_count=w["net_suspicious_port_hits"],
                net_unique_dst_ip=len(w["dst_ips"]),
                net_unique_dst_port=len(w["dst_ports"]),
                net_mean_packet_len=mean_packet_len,
                net_tcp_flags_anomaly=tcp_anomaly,
                # Label
                label=label,
            )
            samples.append(sample)
        
        return samples


def chronological_split(
    samples: List[WindowSample],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
) -> Tuple[List[WindowSample], List[WindowSample], List[WindowSample]]:
    """
    split samples chronologically by window_id
    return (train, val, test) lists
    """
    sorted_samples = sorted(samples, key=lambda s: s.window_id)
    
    n = len(sorted_samples)
    train_end = int(n * train_ratio)
    val_end = int(n * (train_ratio + val_ratio))
    
    train = sorted_samples[:train_end]
    val = sorted_samples[train_end:val_end]
    test = sorted_samples[val_end:]
    
    return train, val, test


def run_quality_checks(samples: List[WindowSample], split_name: str) -> None:
    # run and print quality checks for a sample set
    print(f"\n  Quality checks for {split_name}:")
    
    if not samples:
        print(f"    WARNING: Empty sample set!")
        return
    
    # label distribution
    label_counts = defaultdict(int)
    for s in samples:
        label_counts[s.label] += 1
    
    print(f"    Samples: {len(samples)}")
    print(f"    Labels: benign={label_counts[Label.BENIGN]}, "
          f"malicious={label_counts[Label.MALICIOUS]}, "
          f"unlabeled={label_counts[Label.UNLABELED]}")
    
    # feature ranges
    for feat in SYSCALL_FEATURES + NETWORK_FEATURES:
        values = [getattr(s, feat) for s in samples]
        min_v, max_v = min(values), max(values)
        mean_v = sum(values) / len(values)
        print(f"    {feat}: min={min_v:.2f}, max={max_v:.2f}, mean={mean_v:.2f}")
    
    # validation warnings
    warnings = []
    for s in samples:
        warnings.extend(validate_sample(s))
    
    if warnings:
        print(f"    Validation warnings: {len(warnings)}")
        for w in warnings[:5]:  # Show first 5
            print(f"      - {w}")
    else:
        print(f"    Validation: OK (no warnings)")


def export_csv(samples: List[WindowSample], output_path: str) -> None:
    # export samples to CSV
    if not samples:
        print(f"  Skipping {output_path} (no samples)")
        return
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=ALL_COLUMNS)
        writer.writeheader()
        for sample in samples:
            writer.writerow(sample.to_dict())
    
    print(f"  Exported {len(samples)} samples to {output_path}")


def build_dataset(
    input_path: str,
    output_dir: str,
    window_size_sec: float = WINDOW_SIZE_SEC,
    run_checks: bool = True,
) -> None:
    print("=" * 60)
    print("QML-IDS Dataset Builder")
    print("=" * 60)
    
    # make sure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # load events
    print(f"\n[1/5] Loading events from {input_path}...")
    events = load_events(input_path)
    
    if not events:
        print("ERROR: No events loaded. Check input file.")
        return
    
    # print event type distribution
    type_counts = defaultdict(int)
    for e in events:
        type_counts[e.event_type] += 1
    print(f"  Event types: {dict(type_counts)}")
    
    # window and aggregate
    print(f"\n[2/5] Windowing events (window_size={window_size_sec}s)...")
    aggregator = WindowAggregator(window_size_sec)
    for event in events:
        aggregator.add_event(event)
    
    samples = aggregator.finalize(source="local")
    print(f"  Created {len(samples)} window samples")
    
    # split
    print(f"\n[3/5] Splitting chronologically (70/15/15)...")
    train, val, test = chronological_split(samples)
    print(f"  Train: {len(train)}, Val: {len(val)}, Test: {len(test)}")
    
    # quality checks
    if run_checks:
        print(f"\n[4/5] Running quality checks...")
        run_quality_checks(train, "train")
        run_quality_checks(val, "val")
        run_quality_checks(test, "test")
    
    # export
    print(f"\n[5/5] Exporting CSVs to {output_dir}...")
    export_csv(train, os.path.join(output_dir, "train.csv"))
    export_csv(val, os.path.join(output_dir, "val.csv"))
    export_csv(test, os.path.join(output_dir, "test.csv"))
    
    # export full dataset
    export_csv(samples, os.path.join(output_dir, "full.csv"))
    
    # export schema info
    schema_path = os.path.join(output_dir, "schema_info.json")
    with open(schema_path, 'w') as f:
        json.dump({
            "window_size_sec": window_size_sec,
            "syscall_features": SYSCALL_FEATURES,
            "network_features": NETWORK_FEATURES,
            "metadata_columns": METADATA_COLUMNS,
            "total_events": len(events),
            "total_samples": len(samples),
            "train_samples": len(train),
            "val_samples": len(val),
            "test_samples": len(test),
        }, f, indent=2)
    print(f"  Exported schema info to {schema_path}")
    
    print("\n" + "=" * 60)
    print("Dataset building complete!")
    print("=" * 60)


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Build QML-IDS dataset from events.jsonl"
    )
    parser.add_argument(
        "--input", "-i",
        type=str,
        default="../daemon/policy/events.jsonl",
        help="Path to events.jsonl file"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="./data",
        help="Output directory for CSVs"
    )
    parser.add_argument(
        "--window-size",
        type=float,
        default=WINDOW_SIZE_SEC,
        help=f"Window size in seconds (default: {WINDOW_SIZE_SEC})"
    )
    parser.add_argument(
        "--no-checks",
        action="store_true",
        help="Skip quality checks"
    )
    
    args = parser.parse_args()
    
    build_dataset(
        input_path=args.input,
        output_dir=args.output,
        window_size_sec=args.window_size,
        run_checks=not args.no_checks,
    )


if __name__ == "__main__":
    main()
