def build_filters(ip_src=None, ip_dst=None, port=None, protocol=None, logic="AND"):
    """Builds a BPF-style filter string using AND or OR logic."""
    filters = []
    if ip_src:
        filters.append(f"ip src {ip_src}")
    if ip_dst:
        filters.append(f"ip dst {ip_dst}")
    if port:
        filters.append(f"port {port}")
    if protocol:
        filters.append(protocol)
    filters.append("not port 5004")
    
    # Combine filters based on the selected logic
    return f" {logic.lower()} ".join(filters)