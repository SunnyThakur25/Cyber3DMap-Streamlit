# neuraltrace/dashboard.py
"""
Streamlit dashboard for NeuralTrace.
Visualizes real-time analysis results.
"""
import streamlit as st
import pandas as pd
import json
import asyncio
from neuraltrace.main import NeuralTrace

async def load_results(report_file: str) -> pd.DataFrame:
    """Load analysis results from report."""
    results = []
    with open(report_file, "r") as f:
        for line in f:
            results.append(json.loads(line))
    return pd.DataFrame(results)

def run_dashboard():
    """Run Streamlit dashboard."""
    st.image("logo.png", width=200)  # Add logo
    st.title("NeuralTrace: Network Forensic Dashboard")
    
    st.header("Capture Settings")
    interface = st.text_input("Network Interface", "eth0")
    count = st.number_input("Packet Count", min_value=1, max_value=1000, value=10)
    x_handle = st.text_input("X Handle (optional)")
    
    if st.button("Run Analysis"):
        trace = NeuralTrace(interface)
        result = asyncio.run(trace.run_analysis(count, x_handle))
        asyncio.run(trace.save_report("neuraltrace_report.jsonl"))
        st.success("Analysis completed!")
    
    st.header("Analysis Results")
    try:
        df = asyncio.run(load_results("neuraltrace_report.jsonl"))
        st.dataframe(df[["timestamp", "src_ip", "dst_ip", "attack_type", "anomaly_score"]])
        st.subheader("Attack Type Distribution")
        st.bar_chart(df["attack_type"].value_counts())
    except:
        st.write("No results available. Run an analysis first.")

if __name__ == "__main__":
    run_dashboard()


