"""
Stretch goal 4: Data lineage visualization.
Generates DOT (Graphviz) format and ASCII art for data flow graphs.
"""

from .models import DataFlow, DataCategory


def generate_dot(flows: list[DataFlow], services_regions: dict[str, str]) -> str:
    lines = [
        'digraph data_flows {',
        '  rankdir=LR;',
        '  node [shape=box, style=filled];',
        '',
    ]

    eu_services, non_eu_services = [], []
    all_nodes = set()
    for f in flows:
        all_nodes.add(f.from_service)
        all_nodes.add(f.to_service)

    for node in all_nodes:
        region = services_regions.get(node, "unknown")
        is_eu = region.startswith("eu-")
        color = '"#d4edda"' if is_eu else '"#f8d7da"'
        label = f'"{node}\\n({region})"'
        lines.append(f'  "{node}" [label={label}, fillcolor={color}];')

    lines.append('')

    for f in flows:
        has_pan = DataCategory.CARDHOLDER_PAN in f.data_categories
        has_sad = DataCategory.SENSITIVE_AUTH in f.data_categories
        has_pii = DataCategory.PII in f.data_categories

        edge_color = '"#dc3545"' if (has_pan or has_sad) else '"#fd7e14"' if has_pii else '"#6c757d"'
        style = "dashed" if not f.safeguard and f.crosses_border else "solid"
        safeguard_label = f.safeguard or "NO SAFEGUARD"
        field_sample = ", ".join(f.fields[:2]) + ("..." if len(f.fields) > 2 else "")
        label = f'"{field_sample}\\n[{safeguard_label}]"'

        lines.append(
            f'  "{f.from_service}" -> "{f.to_service}" '
            f'[label={label}, color={edge_color}, style={style}];'
        )

    lines += ['}', '']
    return '\n'.join(lines)


def generate_ascii_lineage(flows: list[DataFlow]) -> str:
    lines = [
        "Data Flow Lineage (ASCII)",
        "=" * 60,
        "Legend: --> (EU transfer)  ~~> (cross-border, no safeguard)  ..> (cross-border, SCC)",
        "",
    ]
    for f in flows:
        if not f.crosses_border:
            arrow = "-->"
        elif f.safeguard in ("scc", "adequacy_decision"):
            arrow = "..>"
        else:
            arrow = "~~> ⚠️"

        cats = [c.value for c in f.data_categories]
        field_str = ", ".join(f.fields[:3]) + ("..." if len(f.fields) > 3 else "")
        lines.append(
            f"  [{f.from_service}]  {arrow}  [{f.to_service}]  |  {field_str}  |  cats: {cats}"
        )
    return "\n".join(lines)
