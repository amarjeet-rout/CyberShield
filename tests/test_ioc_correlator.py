from modules.ioc_correlator import correlate_iocs


def test_url_connected_to_domain():
    iocs = {
        "urls": ["https://example.com/login"],
        "domains": ["example.com"],
        "ip_addresses": [],
        "hashes": [],
    }

    result = correlate_iocs(iocs)

    assert result["node_count"] == 2
    assert result["edge_count"] == 1
    assert result["edges"][0]["relationship"] == "resolves_to_hostname"


def test_multiple_urls_share_domain():
    iocs = {
        "urls": [
            "https://example.com/login",
            "https://example.com/verify",
        ],
        "domains": ["example.com"],
        "ip_addresses": [],
        "hashes": [],
    }

    result = correlate_iocs(iocs)

    assert result["node_count"] == 3
    assert result["edge_count"] == 2
    assert result["connected_components"] == 1


def test_ip_hostname_relationship():
    iocs = {
        "urls": ["http://192.168.1.20/login"],
        "domains": [],
        "ip_addresses": ["192.168.1.20"],
        "hashes": [],
    }

    result = correlate_iocs(iocs)

    assert result["edge_count"] == 1
    assert any(
        node["type"] == "IP Address"
        for node in result["nodes"]
    )


def test_standalone_hash_has_no_invented_relationship():
    iocs = {
        "urls": [],
        "domains": ["example.com"],
        "ip_addresses": [],
        "hashes": ["a" * 64],
    }

    result = correlate_iocs(iocs)

    assert result["edge_count"] == 0
    assert result["connected_components"] == 2
