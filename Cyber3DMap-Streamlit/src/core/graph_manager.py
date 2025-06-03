import networkx as nx
import streamlit as st
from .cve_fetcher import fetch_cve

def store_graph(graph_data: dict):
    """Store graph data in NetworkX."""
    if not graph_data["nodes"]:
        st.error("No nodes to store in graph.")
        return
    try:
        G = nx.DiGraph()
        progress = st.progress(0)
        for i, node in enumerate(graph_data["nodes"]):
            cves = fetch_cve(node["service"])
            if cves is None:
                st.warning(f"No CVEs returned for service: {node['service']}")
                cves = []
            G.add_node(node["ip"], **node, cves=cves)
            progress.progress((i + 1) / len(graph_data["nodes"]))
        for edge in graph_data["edges"]:
            G.add_edge(edge["source"], edge["target"])
        st.session_state.graph = G
        st.write(f"Stored graph with {len(G.nodes())} nodes and {len(G.edges())} edges")
    except Exception as e:
        st.error(f"Error storing graph: {str(e)}")
        st.session_state.graph = nx.DiGraph()

def get_graph() -> dict:
    """Retrieve graph data from NetworkX."""
    if "graph" not in st.session_state or not isinstance(st.session_state.graph, nx.DiGraph):
        st.session_state.graph = nx.DiGraph()
    G = st.session_state.graph
    nodes = [{"ip": n, **d} for n, d in G.nodes(data=True)]
    edges = [{"source": u, "target": v} for u, v in G.edges()]
    return {"nodes": nodes, "edges": edges}