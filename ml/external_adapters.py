"""
Adapters to load and convert ADFA-LD (syscall) and CIC-IDS (network) datasets
into the QML-IDS schema format

Datasets:
- ADFA-LD: Australian Defence Force Academy Linux Dataset (syscall traces)
- CIC-IDS 2017/2018: Canadian Institute for Cybersecurity IDS datasets (network flows)

Usage:
    python external_adapters.py --adfa-path /path/to/ADFA-LD --output ./data/external
    python external_adapters.py --cicids-path /path/to/CIC-IDS2017 --output ./data/external
    python external_adapters.py --all --adfa-path /path/to/ADFA-LD --cicids-path /path/to/CIC-IDS2017 --output ./data/external
"""

import argparse
import os
import csv
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from datetime import datetime
import random

from schema import (
    WINDOW_SIZE_SEC,
    SYSCALL_FEATURES,
    NETWORK_FEATURES,
    ALL_COLUMNS,
    Label,
    WindowSample,
    SyscallSubtype,
    SUSPICIOUS_PORTS,
)


# ADFA-LD DATASET ADAPTER
"""
Key syscall numbers to map to subtypes:
    - 319: memfd_create
    - 10:  mprotect
    - 9:   mmap
    - 105: setuid
    - 106: setgid
    - 56:  clone
    - 272: unshare
    - 308: setns
    - 41:  socket
"""

LINUX_SYSCALL_MAP = {
    # memory operations
    319: SyscallSubtype.MEMFD_CREATE,
    10: SyscallSubtype.MPROTECT_X,
    9: SyscallSubtype.MMAP_X,
    
    # privilege operations
    105: SyscallSubtype.PRIV_CHANGE,
    106: SyscallSubtype.PRIV_CHANGE,
    117: SyscallSubtype.PRIV_CHANGE,
    119: SyscallSubtype.PRIV_CHANGE,
    126: SyscallSubtype.PRIV_CHANGE,
    
    # process/namespace operations
    56: SyscallSubtype.CLONE_FAMILY,
    435: SyscallSubtype.CLONE_FAMILY,
    272: SyscallSubtype.UNSHARE,
    308: SyscallSubtype.SETNS,
    
    # network operations
    41: SyscallSubtype.SOCKET_CREATE,
    
    # exec family
    59: "EXEC", 
    322: "EXEC",
}


def parse_adfa_trace(trace_path: str) -> List[int]:
    # parse a single ADFA-LD trace file into syscall numbers
    syscalls = []
    try:
        with open(trace_path, 'r') as f:
            content = f.read()
            # split by whitespace - space + newline
            for token in content.split():
                token = token.strip()
                if token and token.isdigit():
                    syscalls.append(int(token))
    except Exception as e:
        print(f"  Warning: Could not parse {trace_path}: {e}")
    return syscalls


def window_syscall_trace(
    syscalls: List[int],
    window_size: int = 50,  # number of syscalls per window
    min_trace_len: int = 5,  # minimum syscalls to create a sample
) -> List[Dict[str, int]]:
    if len(syscalls) < min_trace_len:
        return []
    
    windows = []
    
    # if trace is smaller than window, use entire trace as one sample
    if len(syscalls) < window_size:
        chunks = [syscalls]
    else:
        chunks = [syscalls[i:i + window_size] for i in range(0, len(syscalls), window_size)]
        # keep last chunk even if smaller
        chunks = [c for c in chunks if len(c) >= min_trace_len]
    
    for chunk in chunks:
        # count mapped syscalls
        counts = {
            "sc_exec_count": 0,
            "sc_memfd_count": 0,
            "sc_mprotect_x_count": 0,
            "sc_mmap_x_count": 0,
            "sc_priv_change_count": 0,
            "sc_clone_count": 0,
            "sc_namespace_count": 0,
            "sc_socket_create_count": 0,
        }
        
        for sc in chunk:
            mapped = LINUX_SYSCALL_MAP.get(sc)
            if mapped == "EXEC":
                counts["sc_exec_count"] += 1
            elif mapped == SyscallSubtype.MEMFD_CREATE:
                counts["sc_memfd_count"] += 1
            elif mapped == SyscallSubtype.MPROTECT_X:
                counts["sc_mprotect_x_count"] += 1
            elif mapped == SyscallSubtype.MMAP_X:
                counts["sc_mmap_x_count"] += 1
            elif mapped == SyscallSubtype.PRIV_CHANGE:
                counts["sc_priv_change_count"] += 1
            elif mapped == SyscallSubtype.CLONE_FAMILY:
                counts["sc_clone_count"] += 1
            elif mapped in (SyscallSubtype.UNSHARE, SyscallSubtype.SETNS):
                counts["sc_namespace_count"] += 1
            elif mapped == SyscallSubtype.SOCKET_CREATE:
                counts["sc_socket_create_count"] += 1
        
        windows.append(counts)
    
    return windows


def load_adfa_ld(adfa_path: str, max_samples_per_class: int = 5000) -> List[WindowSample]:
    print(f"\n  Loading ADFA-LD from {adfa_path}...")
    
    samples = []
    window_id_counter = 1_000_000
    
    # load normal traces
    normal_dir = os.path.join(adfa_path, "Training_Data_Master")
    if os.path.exists(normal_dir):
        print(f"    Loading normal traces from {normal_dir}...")
        normal_files = list(Path(normal_dir).glob("*.txt"))
        print(f"    Found {len(normal_files)} normal trace files")
        
        normal_count = 0
        for trace_file in normal_files:
            if normal_count >= max_samples_per_class:
                break
            
            syscalls = parse_adfa_trace(str(trace_file))
            windows = window_syscall_trace(syscalls)
            
            for w in windows:
                if normal_count >= max_samples_per_class:
                    break
                
                sample = WindowSample(
                    window_id=window_id_counter,
                    exec_path="adfa_normal",
                    window_start=f"1970-01-01T00:00:{window_id_counter % 60:02d}Z",
                    event_count=100,  # window size
                    source="adfa",
                    label=Label.BENIGN,
                    # syscall features from trace
                    **w,
                    # network features = 0
                    net_packet_out_count=0,
                    net_packet_in_count=0,
                    net_dns_count=0,
                    net_suspicious_port_count=0,
                    net_unique_dst_ip=0,
                    net_unique_dst_port=0,
                    net_mean_packet_len=0.0,
                    net_tcp_flags_anomaly=0.0,
                )
                samples.append(sample)
                window_id_counter += 1
                normal_count += 1
        
        print(f"    Loaded {normal_count} normal windows")
    else:
        print(f"    Warning: Normal directory not found: {normal_dir}")
    
    # load attack traces
    attack_dir = os.path.join(adfa_path, "Attack_Data_Master")
    if os.path.exists(attack_dir):
        print(f"    Loading attack traces from {attack_dir}...")
        
        attack_count = 0
        for attack_type_dir in Path(attack_dir).iterdir():
            if not attack_type_dir.is_dir():
                continue
            
            attack_type = attack_type_dir.name
            attack_files = list(attack_type_dir.glob("*.txt"))
            print(f"      {attack_type}: {len(attack_files)} files")
            
            for trace_file in attack_files:
                if attack_count >= max_samples_per_class:
                    break
                
                syscalls = parse_adfa_trace(str(trace_file))
                windows = window_syscall_trace(syscalls)
                
                for w in windows:
                    if attack_count >= max_samples_per_class:
                        break
                    
                    sample = WindowSample(
                        window_id=window_id_counter,
                        exec_path=f"adfa_attack_{attack_type}",
                        window_start=f"1970-01-01T00:00:{window_id_counter % 60:02d}Z",
                        event_count=100,
                        source="adfa",
                        label=Label.MALICIOUS,
                        **w,
                        net_packet_out_count=0,
                        net_packet_in_count=0,
                        net_dns_count=0,
                        net_suspicious_port_count=0,
                        net_unique_dst_ip=0,
                        net_unique_dst_port=0,
                        net_mean_packet_len=0.0,
                        net_tcp_flags_anomaly=0.0,
                    )
                    samples.append(sample)
                    window_id_counter += 1
                    attack_count += 1
        
        print(f"    Loaded {attack_count} attack windows")
    else:
        print(f"    Warning: Attack directory not found: {attack_dir}")
    
    print(f"  Total ADFA-LD samples: {len(samples)}")
    return samples


# CIC-IDS 2017 DATASET ADAPTER
"""
Key columns:
    - Destination Port
    - Protocol (TCP=6, UDP=17)
    - Flow Duration
    - Total Fwd Packets
    - Total Backward Packets
    - Flow Bytes/s
    - Flow Packets/s
    - Fwd Packet Length Mean
    - Bwd Packet Length Mean
    - FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count
    - Label (BENIGN or attack type)
"""

# CIC-IDS column mappings
CICIDS_COLUMNS = {
    "dst_port": " Destination Port",
    "protocol": " Protocol",
    "fwd_packets": " Total Fwd Packets",
    "bwd_packets": " Total Bwd Packets",
    "fwd_pkt_len_mean": " Fwd Packet Length Mean",
    "bwd_pkt_len_mean": " Bwd Packet Length Mean",
    "flow_bytes_s": " Flow Bytes/s",
    "fin_flag": " FIN Flag Count",
    "syn_flag": " SYN Flag Count",
    "rst_flag": " RST Flag Count",
    "psh_flag": " PSH Flag Count",
    "ack_flag": " ACK Flag Count",
    "label": " Label",
}


def parse_cicids_row(row: Dict, row_num: int) -> Optional[Dict]:
    """Parse a single CIC-IDS CSV row into our feature format."""
    try:
        # get destination port
        dst_port_raw = row.get(CICIDS_COLUMNS["dst_port"], row.get("Destination Port", "0"))
        try:
            dst_port = int(float(dst_port_raw))
        except:
            dst_port = 0
        
        # get packet counts
        fwd_packets = int(float(row.get(CICIDS_COLUMNS["fwd_packets"], row.get("Total Fwd Packets", 0))))
        bwd_packets = int(float(row.get(CICIDS_COLUMNS["bwd_packets"], row.get("Total Bwd Packets", 0))))
        
        # get packet lengths
        fwd_len = float(row.get(CICIDS_COLUMNS["fwd_pkt_len_mean"], row.get("Fwd Packet Length Mean", 0)) or 0)
        bwd_len = float(row.get(CICIDS_COLUMNS["bwd_pkt_len_mean"], row.get("Bwd Packet Length Mean", 0)) or 0)
        mean_pkt_len = (fwd_len + bwd_len) / 2 if (fwd_len + bwd_len) > 0 else 0
        
        # get TCP flags
        fin = int(float(row.get(CICIDS_COLUMNS["fin_flag"], row.get("FIN Flag Count", 0)) or 0))
        syn = int(float(row.get(CICIDS_COLUMNS["syn_flag"], row.get("SYN Flag Count", 0)) or 0))
        rst = int(float(row.get(CICIDS_COLUMNS["rst_flag"], row.get("RST Flag Count", 0)) or 0))
        psh = int(float(row.get(CICIDS_COLUMNS["psh_flag"], row.get("PSH Flag Count", 0)) or 0))
        ack = int(float(row.get(CICIDS_COLUMNS["ack_flag"], row.get("ACK Flag Count", 0)) or 0))
        
        # compute TCP flag anomaly (unusual combinations)
        total_flags = fin + syn + rst + psh + ack
        anomaly_flags = rst + (1 if (fin > 0 and syn > 0) else 0)  # FIN+SYN is anomalous
        tcp_anomaly = anomaly_flags / max(total_flags, 1)
        
        # get label
        label_raw = row.get(CICIDS_COLUMNS["label"], row.get("Label", "BENIGN"))
        if isinstance(label_raw, str):
            label_raw = label_raw.strip()
        label = Label.BENIGN if label_raw == "BENIGN" else Label.MALICIOUS
        
        # suspicious port check
        suspicious = 1 if dst_port in SUSPICIOUS_PORTS else 0
        
        return {
            "net_packet_out_count": fwd_packets,
            "net_packet_in_count": bwd_packets,
            "net_dns_count": 1 if dst_port == 53 else 0,
            "net_suspicious_port_count": suspicious,
            "net_unique_dst_ip": 1,  # each flow is to one destination
            "net_unique_dst_port": 1,
            "net_mean_packet_len": mean_pkt_len,
            "net_tcp_flags_anomaly": tcp_anomaly,
            "label": label,
            "attack_type": label_raw if label == Label.MALICIOUS else None,
        }
    except Exception as e:
        # skip malformed rows silently
        return None


def load_cicids_2017(
    cicids_path: str,
    max_samples_per_class: int = 5000,
) -> List[WindowSample]:
    print(f"\n  Loading CIC-IDS 2017 from {cicids_path}...")
    
    samples = []
    window_id_counter = 2_000_000  # Different range from ADFA
    
    benign_count = 0
    attack_count = 0
    
    # find all CSV files
    csv_files = list(Path(cicids_path).glob("*.csv"))
    print(f"    Found {len(csv_files)} CSV files")
    
    for csv_file in csv_files:
        print(f"    Processing {csv_file.name}...")
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                
                for row_num, row in enumerate(reader):
                    # skip if we have enough samples
                    if benign_count >= max_samples_per_class and attack_count >= max_samples_per_class:
                        break
                    
                    parsed = parse_cicids_row(row, row_num)
                    if parsed is None:
                        continue
                    
                    label = parsed["label"]
                    
                    # balance classes
                    if label == Label.BENIGN and benign_count >= max_samples_per_class:
                        continue
                    if label == Label.MALICIOUS and attack_count >= max_samples_per_class:
                        continue
                    
                    sample = WindowSample(
                        window_id=window_id_counter,
                        exec_path=f"cicids_{parsed.get('attack_type', 'benign') or 'benign'}",
                        window_start=f"1970-01-01T00:00:{window_id_counter % 60:02d}Z",
                        event_count=parsed["net_packet_out_count"] + parsed["net_packet_in_count"],
                        source="cic",
                        label=label,
                        # syscall features = 0 (network-only dataset)
                        sc_exec_count=0,
                        sc_memfd_count=0,
                        sc_mprotect_x_count=0,
                        sc_mmap_x_count=0,
                        sc_priv_change_count=0,
                        sc_clone_count=0,
                        sc_namespace_count=0,
                        sc_socket_create_count=0,
                        # network features from flow
                        net_packet_out_count=parsed["net_packet_out_count"],
                        net_packet_in_count=parsed["net_packet_in_count"],
                        net_dns_count=parsed["net_dns_count"],
                        net_suspicious_port_count=parsed["net_suspicious_port_count"],
                        net_unique_dst_ip=parsed["net_unique_dst_ip"],
                        net_unique_dst_port=parsed["net_unique_dst_port"],
                        net_mean_packet_len=parsed["net_mean_packet_len"],
                        net_tcp_flags_anomaly=parsed["net_tcp_flags_anomaly"],
                    )
                    samples.append(sample)
                    window_id_counter += 1
                    
                    if label == Label.BENIGN:
                        benign_count += 1
                    else:
                        attack_count += 1
        
        except Exception as e:
            print(f"      Error processing {csv_file.name}: {e}")
    
    print(f"    Loaded {benign_count} benign, {attack_count} attack samples")
    print(f"  Total CIC-IDS samples: {len(samples)}")
    return samples


# DATASET MERGING
def merge_and_export(
    local_samples: List[WindowSample],
    adfa_samples: List[WindowSample],
    cicids_samples: List[WindowSample],
    output_dir: str,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
) -> None:
    print(f"\n  Merging datasets...")
    
    os.makedirs(output_dir, exist_ok=True)
    
    def split_samples(samples: List[WindowSample]) -> Tuple[List, List, List]:
        # split samples into train/val/test
        random.shuffle(samples)
        n = len(samples)
        train_end = int(n * train_ratio)
        val_end = int(n * (train_ratio + val_ratio))
        return samples[:train_end], samples[train_end:val_end], samples[val_end:]
    
    # split each source
    local_train, local_val, local_test = split_samples(local_samples) if local_samples else ([], [], [])
    adfa_train, adfa_val, adfa_test = split_samples(adfa_samples) if adfa_samples else ([], [], [])
    cic_train, cic_val, cic_test = split_samples(cicids_samples) if cicids_samples else ([], [], [])
    
    # merge
    train = local_train + adfa_train + cic_train
    val = local_val + adfa_val + cic_val
    test = local_test + adfa_test + cic_test
    
    # shuffle merged sets
    random.shuffle(train)
    random.shuffle(val)
    random.shuffle(test)
    
    print(f"    Train: {len(train)} (local={len(local_train)}, adfa={len(adfa_train)}, cic={len(cic_train)})")
    print(f"    Val:   {len(val)} (local={len(local_val)}, adfa={len(adfa_val)}, cic={len(cic_val)})")
    print(f"    Test:  {len(test)} (local={len(local_test)}, adfa={len(adfa_test)}, cic={len(cic_test)})")
    
    # export CSVs
    def export_csv(samples: List[WindowSample], path: str):
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=ALL_COLUMNS)
            writer.writeheader()
            for s in samples:
                writer.writerow(s.to_dict())
        print(f"    Exported {len(samples)} samples to {path}")
    
    export_csv(train, os.path.join(output_dir, "train.csv"))
    export_csv(val, os.path.join(output_dir, "val.csv"))
    export_csv(test, os.path.join(output_dir, "test.csv"))
    
    # export metadata
    metadata = {
        "total_samples": len(train) + len(val) + len(test),
        "train_samples": len(train),
        "val_samples": len(val),
        "test_samples": len(test),
        "sources": {
            "local": len(local_samples) if local_samples else 0,
            "adfa": len(adfa_samples) if adfa_samples else 0,
            "cicids": len(cicids_samples) if cicids_samples else 0,
        },
        "class_distribution": {
            "train_benign": sum(1 for s in train if s.label == Label.BENIGN),
            "train_malicious": sum(1 for s in train if s.label == Label.MALICIOUS),
            "test_benign": sum(1 for s in test if s.label == Label.BENIGN),
            "test_malicious": sum(1 for s in test if s.label == Label.MALICIOUS),
        },
    }
    
    with open(os.path.join(output_dir, "merged_metadata.json"), 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"\n  Dataset merge complete!")
    print(f"    Benign:    train={metadata['class_distribution']['train_benign']}, "
          f"test={metadata['class_distribution']['test_benign']}")
    print(f"    Malicious: train={metadata['class_distribution']['train_malicious']}, "
          f"test={metadata['class_distribution']['test_malicious']}")


def main():
    parser = argparse.ArgumentParser(
        description="Load and convert external datasets for QML-IDS"
    )
    parser.add_argument(
        "--adfa-path",
        type=str,
        default=None,
        help="Path to ADFA-LD dataset directory"
    )
    parser.add_argument(
        "--cicids-path",
        type=str,
        default=None,
        help="Path to CIC-IDS 2017 CSV directory"
    )
    parser.add_argument(
        "--local-csv",
        type=str,
        default=None,
        help="Path to local full.csv (from dataset_builder.py)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="./data/merged",
        help="Output directory for merged dataset"
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=5000,
        help="Maximum samples per class per dataset"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Load all available datasets"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("QML-IDS External Dataset Adapter")
    print("=" * 60)
    
    # load local data
    local_samples = []
    if args.local_csv and os.path.exists(args.local_csv):
        print(f"\n  Loading local data from {args.local_csv}...")
        import pandas as pd
        df = pd.read_csv(args.local_csv)
        for _, row in df.iterrows():
            sample = WindowSample(
                window_id=int(row["window_id"]),
                exec_path=str(row["exec_path"]),
                window_start=str(row["window_start"]),
                event_count=int(row["event_count"]),
                source=str(row["source"]),
                label=int(row["label"]),
                sc_exec_count=int(row["sc_exec_count"]),
                sc_memfd_count=int(row["sc_memfd_count"]),
                sc_mprotect_x_count=int(row["sc_mprotect_x_count"]),
                sc_mmap_x_count=int(row["sc_mmap_x_count"]),
                sc_priv_change_count=int(row["sc_priv_change_count"]),
                sc_clone_count=int(row["sc_clone_count"]),
                sc_namespace_count=int(row["sc_namespace_count"]),
                sc_socket_create_count=int(row["sc_socket_create_count"]),
                net_packet_out_count=int(row["net_packet_out_count"]),
                net_packet_in_count=int(row["net_packet_in_count"]),
                net_dns_count=int(row["net_dns_count"]),
                net_suspicious_port_count=int(row["net_suspicious_port_count"]),
                net_unique_dst_ip=int(row["net_unique_dst_ip"]),
                net_unique_dst_port=int(row["net_unique_dst_port"]),
                net_mean_packet_len=float(row["net_mean_packet_len"]),
                net_tcp_flags_anomaly=float(row["net_tcp_flags_anomaly"]),
            )
            local_samples.append(sample)
        print(f"    Loaded {len(local_samples)} local samples")
    
    # load ADFA-LD
    adfa_samples = []
    if args.adfa_path and os.path.exists(args.adfa_path):
        adfa_samples = load_adfa_ld(args.adfa_path, args.max_samples)
    elif args.adfa_path:
        print(f"\n  Warning: ADFA-LD path not found: {args.adfa_path}")
    
    # load CIC-IDS
    cicids_samples = []
    if args.cicids_path and os.path.exists(args.cicids_path):
        cicids_samples = load_cicids_2017(args.cicids_path, args.max_samples)
    elif args.cicids_path:
        print(f"\n  Warning: CIC-IDS path not found: {args.cicids_path}")
    
    # merge and export
    if local_samples or adfa_samples or cicids_samples:
        merge_and_export(
            local_samples=local_samples,
            adfa_samples=adfa_samples,
            cicids_samples=cicids_samples,
            output_dir=args.output,
        )
    else:
        print("\n  ERROR: No data loaded. Provide at least one dataset path.")
        print("\n  Example usage:")
        print("    python external_adapters.py --adfa-path /path/to/ADFA-LD --output ./data/merged")
        print("    python external_adapters.py --cicids-path /path/to/CIC-IDS2017 --output ./data/merged")
        print("    python external_adapters.py --local-csv ./data/full.csv --adfa-path /path/to/ADFA-LD --output ./data/merged")


if __name__ == "__main__":
    main()
