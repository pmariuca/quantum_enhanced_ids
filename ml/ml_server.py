import socket
import json
import os
import torch
import numpy as np
from pathlib import Path
from train_qml import DualEncoderQML, SYSCALL_FEATURES, NETWORK_FEATURES

SOCKET_PATH = "/run/qks/qks_ml.sock"
MODEL_PATH  = Path("models/qml_dual_encoder/best_model.pt")
THRESHOLD   = 0.5

def load_model():
    checkpoint = torch.load(MODEL_PATH, weights_only=False)
    
    # Load normalization params
    import json as _json
    with open(MODEL_PATH.parent / "norm_params.json") as f:
        norm = _json.load(f)
    
    model = DualEncoderQML()
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    return model, norm

def infer(model, norm, data: dict) -> float:
    sc_raw  = np.array([[data.get(f, 0.0) for f in SYSCALL_FEATURES]], dtype=np.float32)
    net_raw = np.array([[data.get(f, 0.0) for f in NETWORK_FEATURES]], dtype=np.float32)
    
    # Apply same normalization as training
    sc_mean  = np.array(norm["syscall_mean"], dtype=np.float32)
    sc_std   = np.array(norm["syscall_std"], dtype=np.float32)
    net_mean = np.array(norm["network_mean"], dtype=np.float32)
    net_std  = np.array(norm["network_std"], dtype=np.float32)
    
    sc_norm  = (sc_raw - sc_mean) / sc_std
    net_norm = (net_raw - net_mean) / net_std
    
    with torch.no_grad():
        prob = model(
            torch.tensor(sc_norm, dtype=torch.float32),
            torch.tensor(net_norm, dtype=torch.float32)
        ).item()
    
    return prob

def main():
    model, norm = load_model()
    print(f"[ML SERVER] Model loaded, listening on {SOCKET_PATH}")
    
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(10)
    
    while True:
        conn, _ = server.accept()
        try:
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                try:
                    parsed = json.loads(data)
                    break
                except json.JSONDecodeError:
                    continue
            
            prob = infer(model, norm, parsed)
            verdict = "DENY" if prob > THRESHOLD else "ALLOW"
            print(f"[ML SERVER] prob={prob:.4f} → {verdict}")
            conn.send(str(prob).encode())
        except Exception as e:
            print(f"[ML SERVER] Error: {e}")
            conn.send(b"0.0")
        finally:
            conn.close()

if __name__ == "__main__":
    main()