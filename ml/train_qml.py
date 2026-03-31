#!/usr/bin/env python3
"""
Quantum Machine Learning Dual-Encoder Model
PennyLane-based hybrid quantum-classical model with separate
quantum circuits for syscall and network feature views.

Architecture:
  - Syscall Encoder: 4-qubit variational circuit
  - Network Encoder: 4-qubit variational circuit
  - Fusion: Concatenate quantum outputs -> Classical FC -> Sigmoid
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
    roc_auc_score, confusion_matrix, classification_report
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

# quantum circuit parameters
N_QUBITS_PER_VIEW = 4  # 4 qubits for syscall, 4 for network
N_LAYERS = 3           # number of variational layers
QUANTUM_OUTPUT_DIM = N_QUBITS_PER_VIEW  # output from each quantum circuit


def create_quantum_device(n_qubits: int, shots: int = None):
    return qml.device("lightning.qubit", wires=n_qubits, shots=shots)


def angle_embedding(features, wires):
    # embed classical features as rotation angles
    for i, wire in enumerate(wires):
        if i < len(features):
            qml.RY(features[i] * np.pi, wires=wire)


def variational_layer(weights, wires):
    # single variational layer with rotations and entanglement
    n_qubits = len(wires)
    
    # single-qubit rotations
    for i, wire in enumerate(wires):
        qml.RX(weights[i, 0], wires=wire)
        qml.RY(weights[i, 1], wires=wire)
        qml.RZ(weights[i, 2], wires=wire)
    
    # entangling gates (ring topology)
    for i in range(n_qubits):
        qml.CNOT(wires=[wires[i], wires[(i + 1) % n_qubits]])


def create_syscall_circuit():
    # create quantum circuit for syscall features
    dev = create_quantum_device(N_QUBITS_PER_VIEW)
    
    @qml.qnode(dev, interface="torch", diff_method="adjoint")
    def circuit(inputs, weights):
        wires = list(range(N_QUBITS_PER_VIEW))
        
        # feature embedding
        angle_embedding(inputs, wires)
        
        # variational layers
        for layer in range(N_LAYERS):
            variational_layer(weights[layer], wires)
        
        # measure expectation values
        return [qml.expval(qml.PauliZ(w)) for w in wires]
    
    return circuit


def create_network_circuit():
    # create quantum circuit for network features
    dev = create_quantum_device(N_QUBITS_PER_VIEW)
    
    @qml.qnode(dev, interface="torch", diff_method="adjoint")
    def circuit(inputs, weights):
        wires = list(range(N_QUBITS_PER_VIEW))
        
        # feature embedding
        angle_embedding(inputs, wires)
        
        # variational layers
        for layer in range(N_LAYERS):
            variational_layer(weights[layer], wires)
        
        # measure expectation values
        return [qml.expval(qml.PauliZ(w)) for w in wires]
    
    return circuit


class QuantumLayer(nn.Module):
    def __init__(self, circuit_fn, n_qubits: int, n_layers: int, input_dim: int):
        super().__init__()
        self.circuit = circuit_fn()
        self.n_qubits = n_qubits
        self.n_layers = n_layers
        self.input_dim = input_dim
        
        # trainable weights: (n_layers, n_qubits, 3) for RX, RY, RZ
        weight_shape = (n_layers, n_qubits, 3)
        self.weights = nn.Parameter(
            torch.randn(weight_shape) * 0.1
        )
        
        # classical preprocessing to match qubit count
        if input_dim != n_qubits:
            self.preprocess = nn.Linear(input_dim, n_qubits)
        else:
            self.preprocess = nn.Identity()
    
    def forward(self, x):
        batch_size = x.shape[0]
        
        # preprocess features to match qubit count
        x = self.preprocess(x)
        
        # normalize to [0, 1] for angle embedding
        x = torch.sigmoid(x)
        
        # process each sample through quantum circuit
        outputs = []
        for i in range(batch_size):
            result = self.circuit(x[i], self.weights)
            # stack expectation values into tensor
            if isinstance(result, list):
                result = torch.stack(result)
            outputs.append(result)
        
        # convert to float32 (quantum circuit outputs float64)
        return torch.stack(outputs).float()


class DualEncoderQML(nn.Module):
    def __init__(self, dropout: float = 0.2):
        super().__init__()
        
        # quantum encoders for each view
        self.syscall_encoder = QuantumLayer(
            create_syscall_circuit,
            n_qubits=N_QUBITS_PER_VIEW,
            n_layers=N_LAYERS,
            input_dim=len(SYSCALL_FEATURES)
        )
        
        self.network_encoder = QuantumLayer(
            create_network_circuit,
            n_qubits=N_QUBITS_PER_VIEW,
            n_layers=N_LAYERS,
            input_dim=len(NETWORK_FEATURES)
        )
        
        # classical fusion layers
        fusion_input_dim = 2 * QUANTUM_OUTPUT_DIM  # 8 total from both circuits
        self.fusion = nn.Sequential(
            nn.Linear(fusion_input_dim, 16),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(8, 1),
            nn.Sigmoid()
        )
    
    def forward(self, syscall_features, network_features):
        # encode each view
        syscall_out = self.syscall_encoder(syscall_features)
        network_out = self.network_encoder(network_features)
        
        # concatenate quantum outputs
        fused = torch.cat([syscall_out, network_out], dim=1)
        
        # classical fusion
        return self.fusion(fused).squeeze(-1)


def load_data(data_dir: Path, batch_size: int = 32):
    def load_split(path: Path):
        df = pd.read_csv(path)
        
        # extract feature columns
        sc_cols = [c for c in SYSCALL_FEATURES if c in df.columns]
        net_cols = [c for c in NETWORK_FEATURES if c in df.columns]
        
        # fill missing columns with zeros
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
    
    # load splits
    train_sc, train_net, train_y = load_split(data_dir / "train.csv")
    val_sc, val_net, val_y = load_split(data_dir / "val.csv")
    test_sc, test_net, test_y = load_split(data_dir / "test.csv")
    
    # normalize features
    sc_mean, sc_std = train_sc.mean(axis=0), train_sc.std(axis=0) + 1e-8
    net_mean, net_std = train_net.mean(axis=0), train_net.std(axis=0) + 1e-8
    
    train_sc = (train_sc - sc_mean) / sc_std
    val_sc = (val_sc - sc_mean) / sc_std
    test_sc = (test_sc - sc_mean) / sc_std
    
    train_net = (train_net - net_mean) / net_std
    val_net = (val_net - net_mean) / net_std
    test_net = (test_net - net_mean) / net_std
    
    # create DataLoaders
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
    
    # save normalization params for inference
    norm_params = {
        "syscall_mean": sc_mean.tolist(),
        "syscall_std": sc_std.tolist(),
        "network_mean": net_mean.tolist(),
        "network_std": net_std.tolist()
    }
    
    return train_loader, val_loader, test_loader, norm_params


# training
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
    
    avg_loss = total_loss / len(loader)
    acc = accuracy_score(all_labels, all_preds)
    
    return avg_loss, acc


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
    
    avg_loss = total_loss / len(loader)
    
    metrics = {
        "loss": avg_loss,
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
    epochs: int = 15,
    batch_size: int = 32,
    learning_rate: float = 0.1,
    patience: int = 3,
    device: str = "cpu"
):
    """Full training pipeline."""
    
    print("\n" + "=" * 60)
    print("QML-IDS Dual-Encoder Training")
    print("=" * 60)
    
    # setup
    output_dir.mkdir(parents=True, exist_ok=True)
    device = torch.device(device)
    
    # load data
    print(f"\n  Loading data from {data_dir}...")
    train_loader, val_loader, test_loader, norm_params = load_data(data_dir, batch_size)
    print(f"    Train batches: {len(train_loader)}")
    print(f"    Val batches:   {len(val_loader)}")
    print(f"    Test batches:  {len(test_loader)}")
    
    # initialize model
    print("\n  Initializing Dual-Encoder QML model...")
    print(f"    Qubits per view: {N_QUBITS_PER_VIEW}")
    print(f"    Variational layers: {N_LAYERS}")
    model = DualEncoderQML(dropout=0.2).to(device)
    
    # count parameters
    n_params = sum(p.numel() for p in model.parameters())
    n_quantum_params = sum(
        p.numel() for name, p in model.named_parameters() 
        if "encoder" in name and "weights" in name
    )
    print(f"    Total parameters: {n_params}")
    print(f"    Quantum parameters: {n_quantum_params}")
    
    # loss and optimizer
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=5
    )
    
    # training loop
    print(f"\n  Training for up to {epochs} epochs...")
    best_val_loss = float("inf")
    best_epoch = 0
    history = {"train_loss": [], "train_acc": [], "val_loss": [], "val_acc": []}
    
    start_time = time.time()
    
    for epoch in range(epochs):
        epoch_start = time.time()
        
        # train
        train_loss, train_acc = train_epoch(
            model, train_loader, criterion, optimizer, device
        )
        
        # validate
        val_metrics, _, _, _ = evaluate(model, val_loader, criterion, device)
        val_loss = val_metrics["loss"]
        val_acc = val_metrics["accuracy"]
        
        # update scheduler
        scheduler.step(val_loss)
        
        # record history
        history["train_loss"].append(train_loss)
        history["train_acc"].append(train_acc)
        history["val_loss"].append(val_loss)
        history["val_acc"].append(val_acc)
        
        epoch_time = time.time() - epoch_start
        
        print(f"\n  Epoch {epoch + 1}/{epochs} ({epoch_time:.1f}s)")
        print(f"    Train Loss: {train_loss:.4f}, Acc: {train_acc:.4f}")
        print(f"    Val   Loss: {val_loss:.4f}, Acc: {val_acc:.4f}, F1: {val_metrics['f1']:.4f}")
        
        # save best model
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
        
        # early stopping
        if epoch - best_epoch + 1 >= patience:
            print(f"\n  Early stopping at epoch {epoch + 1} (no improvement for {patience} epochs)")
            break
    
    total_time = time.time() - start_time
    
    # load best model for final evaluation
    print(f"\n  Loading best model from epoch {best_epoch}...")
    checkpoint = torch.load(output_dir / "best_model.pt", weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    
    # final test evaluation
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
    
    # confusion matrix
    cm = confusion_matrix(test_labels, test_preds)
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0,0]:5d}  FP={cm[0,1]:5d}")
    print(f"    FN={cm[1,0]:5d}  TP={cm[1,1]:5d}")
    
    # save results
    results = {
        "model_type": "DualEncoderQML",
        "config": {
            "n_qubits_per_view": N_QUBITS_PER_VIEW,
            "n_layers": N_LAYERS,
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
    parser = argparse.ArgumentParser(description="Train QML-IDS Dual-Encoder Model")
    parser.add_argument(
        "--data-dir", type=str, default="./data/external",
        help="Directory containing train.csv, val.csv, test.csv"
    )
    parser.add_argument(
        "--output-dir", type=str, default="./models/qml_dual_encoder",
        help="Directory to save model and results"
    )
    parser.add_argument("--epochs", type=int, default=50, help="Max epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=0.01, help="Learning rate")
    parser.add_argument("--patience", type=int, default=10, help="Early stopping patience")
    parser.add_argument(
        "--device", type=str, default="cpu",
        help="Device: cpu or cuda"
    )
    
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
