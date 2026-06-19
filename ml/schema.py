"""
QML-IDS Dataset Schema Definition
=================================
Defines the sample structure, windowing strategy, and feature schema
for the quantum machine learning intrusion detection system.

This file is the single source of truth for:
- Window configuration
- Feature column names and types
- Label definitions
- Event type mappings
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
from enum import IntEnum

# WINDOW CONFIGURATION
WINDOW_SIZE_SEC = 5.0  # time window in seconds
GROUPING_KEY = "exec_path"  # primary grouping key (stable across PID recycling)
FALLBACK_KEY = "HOST"  # for events without process context (PACKET_IN)

# event type mapping
class EventType(IntEnum):
    EXEC = 1
    SYSCALL = 2
    PACKET = 3
    DNS = 4
    PACKET_IN = 5

EVENT_TYPE_NAMES = {
    "EXEC": EventType.EXEC,
    "SYSCALL": EventType.SYSCALL,
    "PACKET": EventType.PACKET,
    "DNS": EventType.DNS,
    "PACKET_IN": EventType.PACKET_IN,
}

# syscall subtype mapping
class SyscallSubtype(IntEnum):
    MEMFD_CREATE = 1
    MPROTECT_X = 2
    MMAP_X = 3
    PRIV_CHANGE = 4  # setuid/setgid/setres*/capset
    CLONE_FAMILY = 5  # clone / clone3
    UNSHARE = 6
    SETNS = 7
    SOCKET_CREATE = 8

# suspicious ports
SUSPICIOUS_PORTS = {
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    53,     # DNS
    80,     # HTTP
    443,    # HTTPS
    445,    # SMB
    1433,   # MSSQL
    1434,   # MSSQL Browser
    3306,   # MySQL
    3389,   # RDP
    4444,   # Metasploit default
    5432,   # PostgreSQL
    5555,   # Android ADB
    5900,   # VNC
    6379,   # Redis
    8080,   # HTTP Alt
    8443,   # HTTPS Alt
    9001,   # Tor
    27017,  # MongoDB
}

# feature schema
# metadata columns
METADATA_COLUMNS = [
    "window_id",       # int: time bucket identifier
    "exec_path",       # str: grouping key 
    "window_start",    # str: ISO timestamp of window start
    "event_count",     # int: total events in this window
    "source",          # str: dataset origin: "local", "adfa", "cic"
]

# syscall view features (8 columns)
SYSCALL_FEATURES = [
    "sc_exec_count",           # int: EXEC events in window
    "sc_memfd_count",          # int: memfd_create calls
    "sc_mprotect_x_count",     # int: mprotect with PROT_EXEC
    "sc_mmap_x_count",         # int: mmap with PROT_EXEC
    "sc_priv_change_count",    # int: setuid/setgid/capset
    "sc_clone_count",          # int: clone/clone3
    "sc_namespace_count",      # int: unshare + setns
    "sc_socket_create_count",  # int: socket() calls
]

# network view features (8 columns)
NETWORK_FEATURES = [
    "net_packet_out_count",       # int: outbound TCP SYN
    "net_packet_in_count",        # int: inbound TCP SYN
    "net_dns_count",              # int: DNS queries
    "net_suspicious_port_count",  # int: connections to suspicious ports
    "net_unique_dst_ip",          # int: distinct destination IPs
    "net_unique_dst_port",        # int: distinct destination ports
    "net_mean_packet_len",        # float: average packet length
    "net_tcp_flags_anomaly",      # float: ratio of unusual flag combinations
]

# label column
LABEL_COLUMN = "label"  # int: 0=benign, 1=malicious, -1=unlabeled

# all feature columns
ALL_FEATURES = SYSCALL_FEATURES + NETWORK_FEATURES

# all columns in output CSV
ALL_COLUMNS = METADATA_COLUMNS + SYSCALL_FEATURES + NETWORK_FEATURES + [LABEL_COLUMN]


class Label(IntEnum):
    BENIGN = 0
    MALICIOUS = 1
    UNLABELED = -1

# policy to label mapping for local data
POLICY_TO_LABEL = {
    "ALLOW": Label.BENIGN,
    "DENY": Label.MALICIOUS,
    "UNKNOWN": Label.UNLABELED, 
}


@dataclass
class RawEvent:
    # parsed event from JSONL
    ts_daemon: str
    event_id: int
    event_type: str
    policy: str
    reason: str
    
    # process context (may be None for some event types)
    pid: Optional[int] = None
    ppid: Optional[int] = None
    uid: Optional[int] = None
    exec_path: Optional[str] = None

    
    # PACKET/DNS specific
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    packet_len: Optional[int] = None
    tcp_flags: Optional[str] = None
    
    # DNS specific
    qname: Optional[str] = None
    qtype: Optional[int] = None
    
    # SYSCALL specific
    sc_nr: Optional[int] = None
    sc_subtype: Optional[int] = None
    sc_flags: Optional[str] = None
    sc_prot: Optional[str] = None


@dataclass
class WindowSample:
    # one sample = one aggregated window
    # metadata
    window_id: int
    exec_path: str
    window_start: str
    event_count: int
    source: str
    
    # syscall features
    sc_exec_count: int = 0
    sc_memfd_count: int = 0
    sc_mprotect_x_count: int = 0
    sc_mmap_x_count: int = 0
    sc_priv_change_count: int = 0
    sc_clone_count: int = 0
    sc_namespace_count: int = 0
    sc_socket_create_count: int = 0
    
    # network features
    net_packet_out_count: int = 0
    net_packet_in_count: int = 0
    net_dns_count: int = 0
    net_suspicious_port_count: int = 0
    net_unique_dst_ip: int = 0
    net_unique_dst_port: int = 0
    net_mean_packet_len: float = 0.0
    net_tcp_flags_anomaly: float = 0.0
    
    # label
    label: int = Label.UNLABELED
    
    def to_dict(self) -> Dict:
        return {
            "window_id": self.window_id,
            "exec_path": self.exec_path,
            "window_start": self.window_start,
            "event_count": self.event_count,
            "source": self.source,
            "sc_exec_count": self.sc_exec_count,
            "sc_memfd_count": self.sc_memfd_count,
            "sc_mprotect_x_count": self.sc_mprotect_x_count,
            "sc_mmap_x_count": self.sc_mmap_x_count,
            "sc_priv_change_count": self.sc_priv_change_count,
            "sc_clone_count": self.sc_clone_count,
            "sc_namespace_count": self.sc_namespace_count,
            "sc_socket_create_count": self.sc_socket_create_count,
            "net_packet_out_count": self.net_packet_out_count,
            "net_packet_in_count": self.net_packet_in_count,
            "net_dns_count": self.net_dns_count,
            "net_suspicious_port_count": self.net_suspicious_port_count,
            "net_unique_dst_ip": self.net_unique_dst_ip,
            "net_unique_dst_port": self.net_unique_dst_port,
            "net_mean_packet_len": self.net_mean_packet_len,
            "net_tcp_flags_anomaly": self.net_tcp_flags_anomaly,
            "label": self.label,
        }


# utility functions
def compute_window_id(ts_iso: str, window_size_sec: float = WINDOW_SIZE_SEC) -> int:
    ts = datetime.fromisoformat(ts_iso.replace('Z', '+00:00'))
    epoch = ts.timestamp()
    return int(epoch // window_size_sec)


def window_id_to_timestamp(window_id: int, window_size_sec: float = WINDOW_SIZE_SEC) -> str:
    epoch = window_id * window_size_sec
    return datetime.utcfromtimestamp(epoch).isoformat() + 'Z'


def is_suspicious_port(port: int) -> bool:
    return port in SUSPICIOUS_PORTS


def get_grouping_key(event: RawEvent) -> str:
    if event.exec_path and event.exec_path.strip():
        return event.exec_path
    return FALLBACK_KEY


def validate_sample(sample: WindowSample) -> List[str]:
    warnings = []
    
    # check for negative counts
    for col in SYSCALL_FEATURES + ["net_packet_out_count", "net_packet_in_count", 
                                    "net_dns_count", "net_suspicious_port_count",
                                    "net_unique_dst_ip", "net_unique_dst_port"]:
        val = getattr(sample, col)
        if val < 0:
            warnings.append(f"{col} is negative: {val}")
    
    # check for invalid label
    if sample.label not in [Label.BENIGN, Label.MALICIOUS, Label.UNLABELED]:
        warnings.append(f"Invalid label: {sample.label}")
    
    # check for empty window
    if sample.event_count == 0:
        warnings.append("Empty window (event_count=0)")
    
    return warnings


if __name__ == "__main__":
    # print schema summary
    print("=" * 60)
    print("QML-IDS Dataset Schema")
    print("=" * 60)
    print(f"\nWindow size: {WINDOW_SIZE_SEC} seconds")
    print(f"Grouping key: {GROUPING_KEY}")
    print(f"\nTotal features: {len(ALL_FEATURES)}")
    print(f"  - Syscall features: {len(SYSCALL_FEATURES)}")
    print(f"  - Network features: {len(NETWORK_FEATURES)}")
    print(f"\nAll columns ({len(ALL_COLUMNS)}):")
    for col in ALL_COLUMNS:
        print(f"  - {col}")
