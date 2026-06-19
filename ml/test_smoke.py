import numpy as np
import torch
from ml_server import infer
from train_qml import SYSCALL_FEATURES, NETWORK_FEATURES

class DummyModel(torch.nn.Module):
    def forward(self, sc, net):
        # Return a fixed probability for test
        return torch.tensor([0.42])

def test_infer_returns_float():
    model = DummyModel()
    norm = {
        "syscall_mean": [0.0] * len(SYSCALL_FEATURES),
        "syscall_std": [1.0] * len(SYSCALL_FEATURES),
        "network_mean": [0.0] * len(NETWORK_FEATURES),
        "network_std": [1.0] * len(NETWORK_FEATURES),
    }
    # Minimal valid input
    data = {f: 0.0 for f in SYSCALL_FEATURES + NETWORK_FEATURES}
    prob = infer(model, norm, data)
    assert isinstance(prob, float)
    assert 0.0 <= prob <= 1.0
