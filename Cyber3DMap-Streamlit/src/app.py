import streamlit as st
import time
import random
from core.parser import parse_nmap
from core.graph_manager import store_graph, get_graph
from core.visualizer import plot_3d_graph
from core.gnn_model import predict_paths
import yaml
import os
import networkx as nx

with open(os.path.join(os.path.dirname(__file__), "configs/config.yaml")) as f:
    config = yaml.safe_load(f)

# Initialize session state
if "graph" not in st.session_state:
    st.session_state.graph = nx.DiGraph()
if "cve_cache" not in st.session_state:
    st.session_state.cve_cache = {}
if "threat_node" not in st.session_state:
    st.session_state.threat_node = None
if "last_update" not in st.session_state:
    st.session_state.last_update = time.time()
if "processing" not in st.session_state:
    st.session_state.processing = False

st.set_page_config(page_title="Cyber3DMap", layout="wide")

st.title("Cyber3DMap - Network Visualizer")
st.markdown("Upload an Nmap XML scan to visualize the network in a GNS3-like 3D map.")

uploaded_file = st.file_uploader("Upload Nmap XML Scan", type=["xml"])
if uploaded_file and not st.session_state.processing:
    st.session_state.processing = True
    try:
        with st.spinner("Processing scan and fetching CVEs..."):
            graph_data = parse_nmap(uploaded_file.read())
            if graph_data["nodes"]:
                store_graph(graph_data)
                if st.session_state.graph.nodes():
                    st.success("Network map updated with CVE data!")
                else:
                    st.error("Failed to store graph. Check error messages above.")
            else:
                st.error("No valid nodes found in the scan.")
    except Exception as e:
        st.error(f"Error processing scan: {str(e)}")
    finally:
        st.session_state.processing = False

graph = get_graph()
if graph["nodes"]:
    # Threat simulation (only if not processing)
    if not st.session_state.processing and time.time() - st.session_state.last_update > config["threat_simulation"]["interval"]:
        nodes = [n["ip"] for n in graph["nodes"]]
        st.session_state.threat_node = random.choice(nodes) if nodes else None
        st.session_state.last_update = time.time()
        st.rerun()

    try:
        st.plotly_chart(plot_3d_graph(graph, st.session_state.threat_node), use_container_width=True)
    except Exception as e:
        st.error(f"Error rendering graph: {str(e)}")

    # GNN Predictions
    if st.button("Predict Attack Paths"):
        try:
            predictions = predict_paths()
            if predictions:
                st.subheader("Attack Path Predictions")
                st.markdown("Predicted attack path scores (higher = more likely target):")
                for node, score in zip(graph["nodes"], predictions):
                    st.write(f"- {node['ip']} ({node['service']}): {score[0]:.2f}")
            else:
                st.warning("No predictions available. Ensure a valid graph is loaded.")
        except Exception as e:
            st.error(f"Error predicting attack paths: {str(e)}")
else:
    st.info("No network data loaded. Upload an Nmap XML scan to begin.")

st.subheader("Network Details")
st.json(graph["nodes"])