import ipaddress
from urllib.parse import urlsplit

import networkx as nx


def correlate_iocs(iocs):
    """
    Build an evidence-based graph of extracted indicators.

    A URL is connected to its hostname. Standalone indicators remain
    separate unless an explicit relationship is present in the input.
    """
    graph = nx.Graph()

    urls = iocs.get("urls", [])
    domains = iocs.get("domains", [])
    ip_addresses = iocs.get("ip_addresses", [])
    hashes = iocs.get("hashes", [])

    # Add all extracted indicators as graph nodes.
    for url in urls:
        graph.add_node(
            f"url:{url}",
            type="URL",
            value=url
        )

    for domain in domains:
        graph.add_node(
            f"domain:{domain}",
            type="Domain",
            value=domain
        )

    for address in ip_addresses:
        graph.add_node(
            f"ip:{address}",
            type="IP Address",
            value=address
        )

    for file_hash in hashes:
        graph.add_node(
            f"hash:{file_hash}",
            type="File Hash",
            value=file_hash
        )

    # Create relationships only when directly established by a URL.
    for url in urls:
        try:
            parsed = urlsplit(url)
            hostname = parsed.hostname

            if not hostname:
                continue

            try:
                ipaddress.ip_address(hostname)
                host_node = f"ip:{hostname}"
                host_type = "IP Address"
            except ValueError:
                host_node = f"domain:{hostname}"
                host_type = "Domain"

            if host_node not in graph:
                graph.add_node(
                    host_node,
                    type=host_type,
                    value=hostname
                )

            graph.add_edge(
                f"url:{url}",
                host_node,
                relationship="resolves_to_hostname",
                evidence=f"Hostname parsed directly from URL: {url}"
            )

        except ValueError:
            continue

    nodes = [
        {
            "id": node_id,
            **attributes
        }
        for node_id, attributes in graph.nodes(data=True)
    ]

    edges = [
        {
            "source": source,
            "target": target,
            **attributes
        }
        for source, target, attributes in graph.edges(data=True)
    ]

    return {
        "graph": graph,
        "nodes": nodes,
        "edges": edges,
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "connected_components": nx.number_connected_components(graph),
    }
