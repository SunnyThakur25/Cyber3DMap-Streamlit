import torch
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
import streamlit as st
import yaml
import os

with open(os.path.join(os.path.dirname(__file__), "../configs/config.yaml")) as f:
    config = yaml.safe_load(f)

class GNN(torch.nn.Module):
    def __init__(self, layer_sizes):
        super(GNN, self).__init__()
        self.convs = torch.nn.ModuleList()
        for i in range(len(layer_sizes) - 1):
            self.convs.append(GCNConv(layer_sizes[i], layer_sizes[i + 1]))

    def forward(self, data):
        x, edge_index = data.x, data.edge_index
        for conv in self.convs[:-1]:
            x = conv(x, edge_index).relu()
        x = self.convs[-1](x, edge_index)
        return x

def get_graph_data():
    """Prepare graph data for GNN."""
    G = st.session_state.graph
    if not G.nodes():
        return None
    node_features = []
    node_map = {}
    for i, (node, data) in enumerate(G.nodes(data=True)):
        cvss_scores = [cve["cvss"] for cve in data["cves"]] if data["cves"] else [0]
        feature = [max(cvss_scores)] + [0] * (config["gnn"]["feature_dim"] - 1)
        node_features.append(feature)
        node_map[node] = i
    edge_index = [[node_map[u], node_map[v]] for u, v in G.edges()]
    return {
        "features": node_features,
        "edge_index": edge_index
    }

def predict_paths():
    """Run GNN to predict attack paths."""
    graph_data = get_graph_data()
    if not graph_data:
        return []
    data = Data(
        x=torch.tensor(graph_data["features"], dtype=torch.float),
        edge_index=torch.tensor(graph_data["edge_index"], dtype=torch.long).t().contiguous()
    )
    model = GNN(config["gnn"]["layers"])
    model.eval()
    with torch.no_grad():
        pred = model(data)
    return pred.numpy().tolist()