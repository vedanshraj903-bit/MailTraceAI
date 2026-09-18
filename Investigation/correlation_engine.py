import json
import re
from pathlib import Path


# ============================================================
# NODE CREATION
# ============================================================

def create_node(node_id, node_type, label, properties=None):
    """
    Create one investigation graph node.
    """

    return {
        "id": node_id,
        "type": node_type,
        "label": label,
        "properties": properties or {}
    }


# ============================================================
# EDGE CREATION
# ============================================================

def create_edge(source, target, relationship, properties=None):
    """
    Create one relationship between two investigation graph nodes.
    """

    return {
        "source": source,
        "target": target,
        "relationship": relationship,
        "properties": properties or {}
    }


# ============================================================
# RELAY HOST EXTRACTION
# ============================================================

def extract_relay_host(received_header):
    """
    Extract the sending hostname from a Received header.

    Handles:
        from mail.example.com [1.2.3.4] by ...
        from mail.example.com [1.2.3.4]\tby ...
        from localhost (localhost [127.0.0.1])\tby ...

    Examples:

        from qvp0086 ([169.254.6.17]) by email.qves.com
        -> qvp0086

        from email.qves.com (email1.qves.net [209.63.151.251])
        -> email.qves.com

        from mail.webnote.net [193.120.211.219]
        -> mail.webnote.net

        from localhost (localhost [127.0.0.1])
        -> localhost
    """

    if not received_header:
        return None

    header = str(received_header).strip()

    # --------------------------------------------------------
    # Received headers normally begin with "from"
    # --------------------------------------------------------

    match = re.match(
        r"^\s*from\s+(.+?)(?:\s+by\s+|\s*\tby\s+|\s+by\t|\tby\s+)",
        header,
        re.IGNORECASE
    )

    if match:
        sender_part = match.group(1).strip()
    else:
        # Fallback:
        # Find "by" even when separated by tabs or unusual spacing.
        match = re.search(
            r"^\s*from\s+(.+?)\s+by\s+",
            header,
            re.IGNORECASE
        )

        if match:
            sender_part = match.group(1).strip()
        else:
            # Last fallback: everything after "from"
            match = re.match(
                r"^\s*from\s+(.+)$",
                header,
                re.IGNORECASE
            )

            if not match:
                return None

            sender_part = match.group(1).strip()

    # --------------------------------------------------------
    # Remove parenthesized information.
    #
    # Example:
    # email.qves.com (email1.qves.net [209.63.151.251])
    #
    # becomes:
    # email.qves.com
    # --------------------------------------------------------

    if "(" in sender_part:
        sender_part = sender_part.split("(", 1)[0].strip()

    # --------------------------------------------------------
    # If hostname is followed by an IP in square brackets,
    # keep the hostname.
    #
    # Example:
    # mail.webnote.net [193.120.211.219]
    #
    # becomes:
    # mail.webnote.net
    # --------------------------------------------------------

    if "[" in sender_part:
        sender_part = sender_part.split("[", 1)[0].strip()

    # --------------------------------------------------------
    # Clean trailing punctuation
    # --------------------------------------------------------

    sender_part = sender_part.strip(" ;,:")

    if not sender_part:
        return None

    # --------------------------------------------------------
    # Use first token if multiple tokens remain.
    # --------------------------------------------------------

    return sender_part.split()[0]


# ============================================================
# NORMALIZE DOMAINS
# ============================================================

def extract_domains(security_data):
    """
    Extract domains regardless of whether the security analyzer
    stores them as a list or dictionary.
    """

    domains = security_data.get("domains", [])

    if isinstance(domains, list):
        return domains

    if isinstance(domains, dict):
        details = domains.get("details", [])

        if isinstance(details, list):
            result = []

            for item in details:
                if isinstance(item, str):
                    result.append(item)

                elif isinstance(item, dict):
                    domain = item.get("domain")

                    if domain:
                        result.append(domain)

            return result

        values = domains.get("values", [])

        if isinstance(values, list):
            return values

    return []


# ============================================================
# NORMALIZE URLS
# ============================================================

def extract_url_details(security_data):
    """
    Extract URL details from the security analyzer output.
    """

    urls = security_data.get("urls", {})

    if isinstance(urls, dict):

        details = urls.get("details", [])

        if isinstance(details, list):
            return details

        values = urls.get("values", [])

        if isinstance(values, list):
            return [
                {
                    "url": value
                }
                for value in values
                if isinstance(value, str)
            ]

    elif isinstance(urls, list):

        result = []

        for item in urls:

            if isinstance(item, str):
                result.append({
                    "url": item
                })

            elif isinstance(item, dict):
                result.append(item)

        return result

    return []


# ============================================================
# CORRELATION ENGINE
# ============================================================

def build_investigation_graph(
    parsed_email,
    security_data,
    geolocation_data
):
    """
    Build the MailTraceAI investigation graph.

    Graph relationships are created only when supported by
    available evidence.
    """

    nodes = []
    edges = []

    # ========================================================
    # 1. EMAIL NODE
    # ========================================================

    email_id = "email:primary"

    subject = (
        parsed_email.get("subject")
        or security_data.get("identity", {}).get("subject")
        or "Analyzed Email"
    )

    message_id = (
        parsed_email.get("message_id")
        or security_data.get("identity", {}).get("message_id")
    )

    email_date = (
        parsed_email.get("date")
        or security_data.get("identity", {}).get("date")
    )

    nodes.append(
        create_node(
            email_id,
            "EMAIL",
            subject,
            {
                "message_id": message_id,
                "date": email_date
            }
        )
    )

    # ========================================================
    # 2. SENDER NODE
    # ========================================================

    sender = (
        parsed_email.get("from")
        or security_data.get("identity", {}).get("from")
    )

    if sender:

        sender_id = f"sender:{sender}"

        nodes.append(
            create_node(
                sender_id,
                "SENDER",
                sender
            )
        )

        edges.append(
            create_edge(
                email_id,
                sender_id,
                "SENT_BY"
            )
        )

    # ========================================================
    # 3. DOMAIN NODES
    # ========================================================

    domains = extract_domains(security_data)

    for domain in domains:

        if not domain:
            continue

        domain = str(domain).strip()

        if not domain:
            continue

        domain_id = f"domain:{domain}"

        nodes.append(
            create_node(
                domain_id,
                "DOMAIN",
                domain
            )
        )

    # ========================================================
    # 4. URL NODES
    # ========================================================

    url_details = extract_url_details(security_data)

    for index, url_data in enumerate(url_details):

        if isinstance(url_data, str):

            url = url_data
            domain = None
            scheme = None
            contains_at_symbol = "@" in url

        else:

            url = url_data.get("url")

            domain = url_data.get("domain")

            scheme = url_data.get("scheme")

            contains_at_symbol = url_data.get(
                "contains_at_symbol",
                "@" in url if url else False
            )

        if not url:
            continue

        url_id = f"url:{index}"

        nodes.append(
            create_node(
                url_id,
                "URL",
                url,
                {
                    "scheme": scheme,
                    "domain": domain,
                    "contains_at_symbol": contains_at_symbol
                }
            )
        )

        # ----------------------------------------------------
        # EMAIL -> URL
        # ----------------------------------------------------

        edges.append(
            create_edge(
                email_id,
                url_id,
                "CONTAINS"
            )
        )

        # ----------------------------------------------------
        # URL -> DOMAIN
        # ----------------------------------------------------

        if domain:

            domain_id = f"domain:{domain}"

            # Make sure domain node exists
            nodes.append(
                create_node(
                    domain_id,
                    "DOMAIN",
                    domain
                )
            )

            edges.append(
                create_edge(
                    url_id,
                    domain_id,
                    "USES_DOMAIN"
                )
            )

    # ========================================================
    # 5. PUBLIC IP NODES
    # ========================================================

    routing = security_data.get(
        "routing",
        {}
    )

    public_ips = routing.get(
        "public_infrastructure_ips",
        []
    )

    for ip in public_ips:

        if not ip:
            continue

        ip_id = f"ip:{ip}"

        nodes.append(
            create_node(
                ip_id,
                "IP",
                ip
            )
        )

    # ========================================================
    # 6. RELAY PATH
    # ========================================================

    relay_path = routing.get(
        "relay_path",
        []
    )

    for relay in relay_path:

        if not isinstance(relay, dict):
            continue

        ip = relay.get("ip")

        raw_header = relay.get(
            "raw",
            ""
        )

        # ----------------------------------------------------
        # Extract relay host
        # ----------------------------------------------------

        relay_host = extract_relay_host(
            raw_header
        )

        # ----------------------------------------------------
        # If no host could be extracted, continue.
        # ----------------------------------------------------

        if not relay_host:
            continue

        host_id = f"relay:{relay_host}"

        # ----------------------------------------------------
        # Create relay host node
        # ----------------------------------------------------

        nodes.append(
            create_node(
                host_id,
                "RELAY_HOST",
                relay_host,
                {
                    "hop": relay.get("hop"),
                    "ip": ip,
                    "classification": relay.get(
                        "classification"
                    )
                }
            )
        )

        # ----------------------------------------------------
        # Connect relay host to IP
        # ----------------------------------------------------

        if ip:

            ip_id = f"ip:{ip}"

            # Make sure IP node exists even when the IP is
            # not in public_infrastructure_ips.
            nodes.append(
                create_node(
                    ip_id,
                    "IP",
                    ip,
                    {
                        "classification":
                            relay.get("classification")
                    }
                )
            )

            header_warning = None

            if "may be forged" in raw_header.lower():

                header_warning = "may be forged"

            edges.append(
                create_edge(
                    host_id,
                    ip_id,
                    "OBSERVED_AT",
                    {
                        "hop": relay.get("hop"),

                        "classification":
                            relay.get(
                                "classification"
                            ),

                        "header_warning":
                            header_warning
                    }
                )
            )

    # ========================================================
    # 7. GEOLOCATION + ASN
    # ========================================================

    if not isinstance(geolocation_data, list):
        geolocation_data = []

    for geo in geolocation_data:

        if not isinstance(geo, dict):
            continue

        if geo.get("status") != "SUCCESS":
            continue

        ip = geo.get("ip")

        if not ip:
            continue

        ip_id = f"ip:{ip}"

        # ----------------------------------------------------
        # COUNTRY
        # ----------------------------------------------------

        country = geo.get("country")

        if country:

            country_code = geo.get(
                "country_code",
                ""
            )

            country_id = (
                f"country:{country_code}"
            )

            nodes.append(
                create_node(
                    country_id,
                    "COUNTRY",
                    country,
                    {
                        "country_code":
                            country_code
                    }
                )
            )

            edges.append(
                create_edge(
                    ip_id,
                    country_id,
                    "LOCATED_IN"
                )
            )

        # ----------------------------------------------------
        # ASN
        # ----------------------------------------------------

        asn = geo.get("asn")

        if asn:

            asn_id = f"asn:{asn}"

            nodes.append(
                create_node(
                    asn_id,
                    "ASN",
                    asn,
                    {
                        "name":
                            geo.get("asn_name"),

                        "domain":
                            geo.get("asn_domain")
                    }
                )
            )

            edges.append(
                create_edge(
                    ip_id,
                    asn_id,
                    "ANNOUNCED_BY"
                )
            )

    # ========================================================
    # 8. REMOVE DUPLICATE NODES
    # ========================================================

    unique_nodes = {}

    for node in nodes:

        unique_nodes[node["id"]] = node

    nodes = list(
        unique_nodes.values()
    )

    # ========================================================
    # 9. REMOVE DUPLICATE EDGES
    # ========================================================

    unique_edges = []

    seen_edges = set()

    for edge in edges:

        edge_key = (
            edge["source"],
            edge["target"],
            edge["relationship"]
        )

        if edge_key not in seen_edges:

            seen_edges.add(
                edge_key
            )

            unique_edges.append(
                edge
            )

    edges = unique_edges

    # ========================================================
    # 10. RETURN GRAPH
    # ========================================================

    return {
        "graph_version": "1.2",

        "node_count":
            len(nodes),

        "edge_count":
            len(edges),

        "nodes":
            nodes,

        "edges":
            edges
    }


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    analysis_file = Path(
        "final_analysis.json"
    )

    if not analysis_file.exists():

        print(
            "ERROR: final_analysis.json not found."
        )

        raise SystemExit(1)

    # --------------------------------------------------------
    # Load analysis
    # --------------------------------------------------------

    with analysis_file.open(
        "r",
        encoding="utf-8"
    ) as file:

        analysis = json.load(file)

    # --------------------------------------------------------
    # Extract pipeline sections
    # --------------------------------------------------------

    parsed_email = analysis[
        "parsed_email"
    ]

    security_data = analysis[
        "security_analysis"
    ]

    geolocation_data = analysis[
        "geolocation"
    ]

    # --------------------------------------------------------
    # Build graph
    # --------------------------------------------------------

    graph = build_investigation_graph(
        parsed_email,
        security_data,
        geolocation_data
    )

    # --------------------------------------------------------
    # Display summary
    # --------------------------------------------------------

    print(
        "=" * 60
    )

    print(
        "MAILTRACEAI INVESTIGATION GRAPH"
    )

    print(
        "=" * 60
    )

    print(
        f"Nodes: {graph['node_count']}"
    )

    print(
        f"Edges: {graph['edge_count']}"
    )

    # ========================================================
    # NODE TYPES
    # ========================================================

    print(
        "\nNODE TYPES:"
    )

    node_types = {}

    for node in graph["nodes"]:

        node_type = node["type"]

        node_types[node_type] = (
            node_types.get(
                node_type,
                0
            ) + 1
        )

    for node_type, count in node_types.items():

        print(
            f"  {node_type}: {count}"
        )

    # ========================================================
    # RELAY RELATIONSHIPS
    # ========================================================

    print(
        "\nRELAY RELATIONSHIPS:"
    )

    for edge in graph["edges"]:

        if edge["relationship"] != "OBSERVED_AT":
            continue

        print(
            f"  {edge['source']} "
            f"--[OBSERVED_AT]--> "
            f"{edge['target']}"
        )

        properties = edge.get(
            "properties",
            {}
        )

        print(
            f"    Hop: "
            f"{properties.get('hop')}"
        )

        print(
            f"    Classification: "
            f"{properties.get('classification')}"
        )

        warning = properties.get(
            "header_warning"
        )

        if warning:

            print(
                f"    Warning: {warning}"
            )

    # ========================================================
    # ALL RELATIONSHIPS
    # ========================================================

    print(
        "\nALL RELATIONSHIPS:"
    )

    for edge in graph["edges"]:

        print(
            f"  {edge['source']} "
            f"--[{edge['relationship']}]--> "
            f"{edge['target']}"
        )

    # ========================================================
    # SAVE GRAPH
    # ========================================================

    output_file = Path(
        "investigation_graph.json"
    )

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            graph,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(
        f"\nGraph saved to: "
        f"{output_file}"
    )