#!/usr/bin/env python3
"""
Multi-View Entangled Quantum Model

Architecture:
  - 8-qubit circuit (4 syscall + 4 network)
  - Cross-view entanglement gates
  - Quantum correlation between feature views
"""

import argparse
import json
import time
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)

import pennylane as qml

SYSCALL_FEATURES = [
    "sc_exec_count", "sc_memfd_count", "sc_mprotect_x_count", "sc_mmap_x_count",
    "sc_priv_change_count", "sc_clone_count", "sc_namespace_count", "sc_socket_create_count"
]

NETWORK_FEATURES = [
    "net_packet_out_count", "net_packet_in_count", "net_dns_count",
    "net_suspicious_port_count", "net_unique_dst_ip", "net_unique_dst_port",
    "net_mean_packet_len", "net_tcp_flags_anomaly"
]

# quantum parameters
N_QUBITS_SYSCALL = 4
N_QUBITS_NETWORK = 4
N_QUBITS_TOTAL = N_QUBITS_SYSCALL + N_QUBITS_NETWORK  # 8
N_LAYERS = 3
N_ENTANGLE_LAYERS = 2  # cross-view entanglement layers


def create_entangled_device():
    return qml.device("lightning.qubit", wires=N_QUBITS_TOTAL)


def encode_features(syscall_feats, network_feats, syscall_wires, network_wires):
    # angle embedding for both views
    for i, wire in enumerate(syscall_wires):
        if i < len(syscall_feats):
            qml.RY(syscall_feats[i] * np.pi, wires=wire)
    
    for i, wire in enumerate(network_wires):
        if i < len(network_feats):
            qml.RY(network_feats[i] * np.pi, wires=wire)


def intra_view_layer(weights, wires):
    # variational layer within a single view
    n_qubits = len(wires)
    
    # rotations
    for i, wire in enumerate(wires):
        qml.RX(weights[i, 0], wires=wire)
        qml.RY(weights[i, 1], wires=wire)
        qml.RZ(weights[i, 2], wires=wire)
    
    # ring entanglement within view
    for i in range(n_qubits):
        qml.CNOT(wires=[wires[i], wires[(i + 1) % n_qubits]])


def cross_view_entanglement(entangle_weights, syscall_wires, network_wires):
    # create entanglement between syscall and network views
    n_pairs = min(len(syscall_wires), len(network_wires))
    
    for i in range(n_pairs):
        # controlled rotations between views
        qml.CRY(entangle_weights[i, 0], wires=[syscall_wires[i], network_wires[i]])
        qml.CRZ(entangle_weights[i, 1], wires=[network_wires[i], syscall_wires[i]])
    
    # additional cross-view CNOT gates
    qml.CNOT(wires=[syscall_wires[0], network_wires[-1]])
    qml.CNOT(wires=[network_wires[0], syscall_wires[-1]])


def create_entangled_circuit():
    dev = create_entangled_device()
    
    syscall_wires = list(range(N_QUBITS_SYSCALL))
    network_wires = list(range(N_QUBITS_SYSCALL, N_QUBITS_TOTAL))
    
    @qml.qnode(dev, interface="torch", diff_method="adjoint")
    def circuit(syscall_feats, network_feats, syscall_weights, network_weights, entangle_weights):
        # feature encoding
        encode_features(syscall_feats, network_feats, syscall_wires, network_wires)
        
        # alternating intra-view and cross-view layers
        for layer in range(N_LAYERS):
            # intra-view processing
            intra_view_layer(syscall_weights[layer], syscall_wires)
            intra_view_layer(network_weights[layer], network_wires)
            
            # cross-view entanglement (every other layer)
            if layer < N_ENTANGLE_LAYERS:
                cross_view_entanglement(
                    entangle_weights[layer], syscall_wires, network_wires
                )
        
        # measure all qubits
        return [qml.expval(qml.PauliZ(w)) for w in range(N_QUBITS_TOTAL)]
    
    return circuit


class EntangledQuantumLayer(nn.Module):
    def __init__(self, syscall_input_dim: int, network_input_dim: int):
        super().__init__()
        
        self.circuit = create_entangled_circuit()
        
        # preprocessing to match qubit counts
        if syscall_input_dim != N_QUBITS_SYSCALL:
            self.syscall_pre = nn.Linear(syscall_input_dim, N_QUBITS_SYSCALL)
        else:
            self.syscall_pre = nn.Identity()
        
        if network_input_dim != N_QUBITS_NETWORK:
            self.network_pre = nn.Linear(network_input_dim, N_QUBITS_NETWORK)
        else:
            self.network_pre = nn.Identity()
        
        # trainable quantum weights
        # intra-view weights: (N_LAYERS, N_QUBITS_PER_VIEW, 3)
        self.syscall_weights = nn.Parameter(
            torch.randn(N_LAYERS, N_QUBITS_SYSCALL, 3) * 0.1
        )
        self.network_weights = nn.Parameter(
            torch.randn(N_LAYERS, N_QUBITS_NETWORK, 3) * 0.1
        )
        
        # cross-view entanglement weights: (N_ENTANGLE_LAYERS, N_PAIRS, 2)
        n_pairs = min(N_QUBITS_SYSCALL, N_QUBITS_NETWORK)
        self.entangle_weights = nn.Parameter(
            torch.randn(N_ENTANGLE_LAYERS, n_pairs, 2) * 0.1
        )
    
    def forward(self, syscall_feats, network_feats):
        batch_size = syscall_feats.shape[0]
        
        # preprocess
        syscall_feats = self.syscall_pre(syscall_feats)
        network_feats = self.network_pre(network_feats)
        
        # normalize to [0, 1]
        syscall_feats = torch.sigmoid(syscall_feats)
        network_feats = torch.sigmoid(network_feats)
        
        # process batch
        outputs = []
        for i in range(batch_size):
            result = self.circuit(
                syscall_feats[i],
                network_feats[i],
                self.syscall_weights,
                self.network_weights,
                self.entangle_weights
            )
            if isinstance(result, list):
                result = torch.stack(result)
            outputs.append(result)
        
        # convert to float32 (quantum circuit outputs float64)
        return torch.stack(outputs).float()


class EntangledMultiViewQML(nn.Module):
    def __init__(self, dropout: float = 0.2):
        super().__init__()
        
        self.quantum_layer = EntangledQuantumLayer(
            syscall_input_dim=len(SYSCALL_FEATURES),
            network_input_dim=len(NETWORK_FEATURES)
        )
        
        # classical fusion
        self.fusion = nn.Sequential(
            nn.Linear(N_QUBITS_TOTAL, 16),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(8, 1),
            nn.Sigmoid()
        )
    
    def forward(self, syscall_features, network_features):
        quantum_out = self.quantum_layer(syscall_features, network_features)
        return self.fusion(quantum_out).squeeze(-1)


def load_data(data_dir: Path, batch_size: int = 32):
    def load_split(path: Path):
        df = pd.read_csv(path)
        
        for col in SYSCALL_FEATURES:
            if col not in df.columns:
                df[col] = 0.0
        for col in NETWORK_FEATURES:
            if col not in df.columns:
                df[col] = 0.0
        
        X_sc = df[SYSCALL_FEATURES].values.astype(np.float32)
        X_net = df[NETWORK_FEATURES].values.astype(np.float32)
        y = df["label"].values.astype(np.float32)
        
        return X_sc, X_net, y
    
    train_sc, train_net, train_y = load_split(data_dir / "train.csv")
    val_sc, val_net, val_y = load_split(data_dir / "val.csv")
    test_sc, test_net, test_y = load_split(data_dir / "test.csv")
    
    # normalize
    sc_mean, sc_std = train_sc.mean(axis=0), train_sc.std(axis=0) + 1e-8
    net_mean, net_std = train_net.mean(axis=0), train_net.std(axis=0) + 1e-8
    
    train_sc = (train_sc - sc_mean) / sc_std
    val_sc = (val_sc - sc_mean) / sc_std
    test_sc = (test_sc - sc_mean) / sc_std
    
    train_net = (train_net - net_mean) / net_std
    val_net = (val_net - net_mean) / net_std
    test_net = (test_net - net_mean) / net_std
    
    train_ds = TensorDataset(
        torch.tensor(train_sc), torch.tensor(train_net), torch.tensor(train_y)
    )
    val_ds = TensorDataset(
        torch.tensor(val_sc), torch.tensor(val_net), torch.tensor(val_y)
    )
    test_ds = TensorDataset(
        torch.tensor(test_sc), torch.tensor(test_net), torch.tensor(test_y)
    )
    
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False)
    
    norm_params = {
        "syscall_mean": sc_mean.tolist(),
        "syscall_std": sc_std.tolist(),
        "network_mean": net_mean.tolist(),
        "network_std": net_std.tolist()
    }
    
    return train_loader, val_loader, test_loader, norm_params


def train_epoch(model, loader, criterion, optimizer, device):
    model.train()
    total_loss = 0.0
    all_preds, all_labels = [], []
    
    for batch_idx, (sc_feat, net_feat, labels) in enumerate(loader):
        sc_feat = sc_feat.to(device)
        net_feat = net_feat.to(device)
        labels = labels.to(device)
        
        optimizer.zero_grad()
        outputs = model(sc_feat, net_feat)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
        preds = (outputs > 0.5).float()
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())
        
        if (batch_idx + 1) % 50 == 0:
            print(f"    Batch {batch_idx + 1}/{len(loader)}, Loss: {loss.item():.4f}")
    
    return total_loss / len(loader), accuracy_score(all_labels, all_preds)


def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss = 0.0
    all_preds, all_probs, all_labels = [], [], []
    
    with torch.no_grad():
        for sc_feat, net_feat, labels in loader:
            sc_feat = sc_feat.to(device)
            net_feat = net_feat.to(device)
            labels = labels.to(device)
            
            outputs = model(sc_feat, net_feat)
            loss = criterion(outputs, labels)
            
            total_loss += loss.item()
            all_probs.extend(outputs.cpu().numpy())
            preds = (outputs > 0.5).float()
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
    
    metrics = {
        "loss": total_loss / len(loader),
        "accuracy": accuracy_score(all_labels, all_preds),
        "precision": precision_score(all_labels, all_preds, zero_division=0),
        "recall": recall_score(all_labels, all_preds, zero_division=0),
        "f1": f1_score(all_labels, all_preds, zero_division=0),
        "auc_roc": roc_auc_score(all_labels, all_probs) if len(set(all_labels)) > 1 else 0.0
    }
    
    return metrics, np.array(all_labels), np.array(all_preds), np.array(all_probs)


def train_model(
    data_dir: Path,
    output_dir: Path,
    epochs: int = 50,
    batch_size: int = 32,
    learning_rate: float = 0.01,
    patience: int = 10,
    device: str = "cpu"
):
    print("\n" + "=" * 60)
    print("QML-IDS Entangled Multi-View Training")
    print("=" * 60)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    device = torch.device(device)
    
    # load data
    print(f"\n  Loading data from {data_dir}...")
    train_loader, val_loader, test_loader, norm_params = load_data(data_dir, batch_size)
    print(f"    Train batches: {len(train_loader)}")
    print(f"    Val batches:   {len(val_loader)}")
    print(f"    Test batches:  {len(test_loader)}")
    
    # initialize model
    print("\n  Initializing Entangled Multi-View QML model...")
    print(f"    Total qubits: {N_QUBITS_TOTAL} ({N_QUBITS_SYSCALL} syscall + {N_QUBITS_NETWORK} network)")
    print(f"    Variational layers: {N_LAYERS}")
    print(f"    Cross-view entanglement layers: {N_ENTANGLE_LAYERS}")
    model = EntangledMultiViewQML(dropout=0.2).to(device)
    
    n_params = sum(p.numel() for p in model.parameters())
    n_quantum_params = sum(
        p.numel() for name, p in model.named_parameters()
        if "weights" in name and "fusion" not in name
    )
    print(f"    Total parameters: {n_params}")
    print(f"    Quantum parameters: {n_quantum_params}")
    
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=5
    )
    
    # training
    print(f"\n  Training for up to {epochs} epochs...")
    best_val_loss = float("inf")
    best_epoch = 0
    history = {"train_loss": [], "train_acc": [], "val_loss": [], "val_acc": []}
    
    start_time = time.time()
    
    for epoch in range(epochs):
        epoch_start = time.time()
        
        train_loss, train_acc = train_epoch(
            model, train_loader, criterion, optimizer, device
        )
        
        val_metrics, _, _, _ = evaluate(model, val_loader, criterion, device)
        val_loss = val_metrics["loss"]
        val_acc = val_metrics["accuracy"]
        
        scheduler.step(val_loss)
        
        history["train_loss"].append(train_loss)
        history["train_acc"].append(train_acc)
        history["val_loss"].append(val_loss)
        history["val_acc"].append(val_acc)
        
        epoch_time = time.time() - epoch_start
        
        print(f"\n  Epoch {epoch + 1}/{epochs} ({epoch_time:.1f}s)")
        print(f"    Train Loss: {train_loss:.4f}, Acc: {train_acc:.4f}")
        print(f"    Val   Loss: {val_loss:.4f}, Acc: {val_acc:.4f}, F1: {val_metrics['f1']:.4f}")
        
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_epoch = epoch + 1
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_loss": val_loss,
                "val_metrics": val_metrics
            }, output_dir / "best_model.pt")
            print(f"    ★ New best model saved!")
        
        if epoch - best_epoch + 1 >= patience:
            print(f"\n  Early stopping at epoch {epoch + 1}")
            break
    
    total_time = time.time() - start_time
    
    # load best and evaluate
    print(f"\n  Loading best model from epoch {best_epoch}...")
    checkpoint = torch.load(output_dir / "best_model.pt", weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    
    print("\n  Evaluating on test set...")
    test_metrics, test_labels, test_preds, test_probs = evaluate(
        model, test_loader, criterion, device
    )
    
    print(f"\n" + "=" * 60)
    print("Test Results")
    print("=" * 60)
    print(f"  Accuracy:  {test_metrics['accuracy']:.4f}")
    print(f"  Precision: {test_metrics['precision']:.4f}")
    print(f"  Recall:    {test_metrics['recall']:.4f}")
    print(f"  F1 Score:  {test_metrics['f1']:.4f}")
    print(f"  AUC-ROC:   {test_metrics['auc_roc']:.4f}")
    
    cm = confusion_matrix(test_labels, test_preds)
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0,0]:5d}  FP={cm[0,1]:5d}")
    print(f"    FN={cm[1,0]:5d}  TP={cm[1,1]:5d}")
    
    # save results
    results = {
        "model_type": "EntangledMultiViewQML",
        "config": {
            "n_qubits_total": N_QUBITS_TOTAL,
            "n_qubits_syscall": N_QUBITS_SYSCALL,
            "n_qubits_network": N_QUBITS_NETWORK,
            "n_layers": N_LAYERS,
            "n_entangle_layers": N_ENTANGLE_LAYERS,
            "epochs_trained": best_epoch,
            "batch_size": batch_size,
            "learning_rate": learning_rate,
            "total_params": n_params,
            "quantum_params": n_quantum_params
        },
        "test_metrics": test_metrics,
        "confusion_matrix": cm.tolist(),
        "training_time_seconds": total_time,
        "timestamp": datetime.now().isoformat()
    }
    
    with open(output_dir / "results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    with open(output_dir / "history.json", "w") as f:
        json.dump(history, f, indent=2)
    
    with open(output_dir / "norm_params.json", "w") as f:
        json.dump(norm_params, f, indent=2)
    
    print(f"\n  Results saved to {output_dir}")
    print(f"  Total training time: {total_time/60:.1f} minutes")
    
    return model, results


def main():
    parser = argparse.ArgumentParser(description="Train QML-IDS Entangled Multi-View Model")
    parser.add_argument(
        "--data-dir", type=str, default="./data/external",
        help="Directory containing train.csv, val.csv, test.csv"
    )
    parser.add_argument(
        "--output-dir", type=str, default="./models/qml_entangled",
        help="Directory to save model and results"
    )
    parser.add_argument("--epochs", type=int, default=50, help="Max epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=0.01, help="Learning rate")
    parser.add_argument("--patience", type=int, default=10, help="Early stopping patience")
    parser.add_argument("--device", type=str, default="cpu", help="Device: cpu or cuda")
    
    args = parser.parse_args()
    
    train_model(
        data_dir=Path(args.data_dir),
        output_dir=Path(args.output_dir),
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        patience=args.patience,
        device=args.device
    )


if __name__ == "__main__":
    main()
