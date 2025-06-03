import xml.etree.ElementTree as ET
import streamlit as st

def parse_nmap(file: bytes) -> dict:
    """Parse Nmap XML scan into nodes and edges."""
    try:
        root = ET.fromstring(file.decode('utf-8'))
        if root.tag != "nmaprun":
            raise ValueError("Invalid Nmap XML: root element must be 'nmaprun'")
        nodes = []
        edges = []
        for host in root.findall("host"):
            ip_elem = host.find("address")
            if ip_elem is None or "addr" not in ip_elem.attrib:
                continue
            ip = ip_elem.attrib["addr"]
            ports = [p.attrib.get("portid", "") for p in host.findall(".//port") if p.attrib.get("portid")]
            service_elem = host.find(".//service")
            service = service_elem.attrib.get("name", "") if service_elem is not None else ""
            product = service_elem.attrib.get("product", "") if service_elem is not None else ""
            version = service_elem.attrib.get("version", "") if service_elem is not None else ""
            nodes.append({"ip": ip, "ports": ports, "service": service, "product": product, "version": version})
            for other_ip in [n["ip"] for n in nodes if n["ip"] != ip][:3]:  # Limit edges for clarity
                edges.append({"source": ip, "target": other_ip})
        if not nodes:
            raise ValueError("No valid hosts found in Nmap XML")
        return {"nodes": nodes, "edges": edges}
    except ET.ParseError as e:
        st.error(f"Invalid XML: {str(e)}. Upload a valid Nmap XML scan.")
        return {"nodes": [], "edges": []}
    except ValueError as e:
        st.error(f"Error processing XML: {str(e)}")
        return {"nodes": [], "edges": []}
    except Exception as e:
        st.error(f"Unexpected error: {str(e)}")
        return {"nodes": [], "edges": []}