import plotly.graph_objects as go
import networkx as nx
import yaml
import os

with open(os.path.join(os.path.dirname(__file__), "../configs/config.yaml")) as f:
    config = yaml.safe_load(f)

def plot_3d_graph(graph: dict, threat_node: str = None) -> go.Figure:
    """Create GNS3-like 3D network map."""
    nodes = graph["nodes"]
    edges = graph["edges"]
    # Build graph for layout
    G = nx.DiGraph()
    for node in nodes:
        G.add_node(node["ip"])
    for edge in edges:
        G.add_edge(edge["source"], edge["target"])
    pos = nx.spring_layout(G, dim=3, seed=config["visualization"]["layout"]["seed"])
    
    # Node positions and colors
    node_x = [pos[n["ip"]][0] * config["visualization"]["layout"]["scale"] for n in nodes]
    node_y = [pos[n["ip"]][1] * config["visualization"]["layout"]["scale"] for n in nodes]
    node_z = [pos[n["ip"]][2] * config["visualization"]["layout"]["scale"] for n in nodes]
    node_colors = [
        config["visualization"]["node_colors"]["high_cvss"] if max([c["cvss"] for c in n["cves"]], default=0) > 7 else
        config["visualization"]["node_colors"]["medium_cvss"] if max([c["cvss"] for c in n["cves"]], default=0) > 4 else
        config["visualization"]["node_colors"]["low_cvss"] for n in nodes
    ]
    if threat_node:
        node_colors = [
            config["visualization"]["node_colors"]["threat"] if n["ip"] == threat_node else c
            for n, c in zip(nodes, node_colors)
        ]
    
    # Edge positions
    edge_x = []
    edge_y = []
    edge_z = []
    for edge in edges:
        src_idx = next(i for i, n in enumerate(nodes) if n["ip"] == edge["source"])
        tgt_idx = next(i for i, n in enumerate(nodes) if n["ip"] == edge["target"])
        edge_x.extend([node_x[src_idx], node_x[tgt_idx], None])
        edge_y.extend([node_y[src_idx], node_y[tgt_idx], None])
        edge_z.extend([node_z[src_idx], node_z[tgt_idx], None])

    # Plotly figure
    fig = go.Figure()
    fig.add_trace(go.Scatter3d(
        x=edge_x, y=edge_y, z=edge_z, mode="lines",
        line=dict(width=2, color=config["visualization"]["edge_color"]), hoverinfo="none"
    ))
    fig.add_trace(go.Scatter3d(
        x=node_x, y=node_y, z=node_z, mode="markers+text",
        text=[f"{n['ip']} ({n['service']})" for n in nodes], textposition="top center",
        marker=dict(size=config["visualization"]["node_size"], color=node_colors),
        hoverinfo="text",
        hovertext=[f"IP: {n['ip']}<br>Service: {n['service']}<br>Ports: {', '.join(n['ports'])}<br>CVEs: {len(n['cves'])}" for n in nodes]
    ))
    fig.update_layout(
        title="3D Network Map",
        scene=dict(
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, title=""),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, title=""),
            zaxis=dict(showgrid=False, zeroline=False, showticklabels=False, title=""),
            bgcolor="white"
        ),
        showlegend=False,
        paper_bgcolor="white",
        font=dict(color="black"),
        margin=dict(l=0, r=0, t=50, b=0)
    )
    return fig