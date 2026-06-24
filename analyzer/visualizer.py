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
        "Legend: --> (intra-EU / adequate)  ~~> (cross-border, NO safeguard ⚠️)  ..> (cross-border, SCC)",
        "        [🔴 PAN/SAD]  [🟠 PII]  [⚫ general]",
        "",
    ]

    # PAN lineage highlight — show the specific chain the challenge asks for
    pan_flows = [f for f in flows if DataCategory.CARDHOLDER_PAN in f.data_categories]
    if pan_flows:
        lines += ["── PAN / Cardholder Data Flows ──────────────────────────", ""]
        for f in pan_flows:
            arrow = "~~> ⚠️" if (f.crosses_border and f.safeguard not in ("scc", "adequacy_decision")) else "-->"
            enc_note = "[encrypted]" if any("encrypt" in x.lower() or "token" in x.lower() for x in f.fields) else "[plaintext ⚠️]"
            border_note = f" [cross-border → {f.to_region}]" if f.crosses_border else ""
            field_str = ", ".join(f.fields[:3]) + ("..." if len(f.fields) > 3 else "")
            lines.append(f"  🔴 [{f.from_service}]  {arrow}  [{f.to_service}]{border_note}")
            lines.append(f"     fields: {field_str}  {enc_note}")
            lines.append("")

    # All other flows
    other_flows = [f for f in flows if DataCategory.CARDHOLDER_PAN not in f.data_categories]
    if other_flows:
        lines += ["── PII / Other Flows ────────────────────────────────────", ""]
        for f in other_flows:
            if not f.crosses_border:
                arrow = "-->"
            elif f.safeguard in ("scc", "adequacy_decision"):
                arrow = "..>"
            else:
                arrow = "~~> ⚠️"
            icon = "🟠" if DataCategory.PII in f.data_categories else "⚫"
            border_note = f" [cross-border → {f.to_region}, safeguard: {f.safeguard or 'NONE'}]" if f.crosses_border else ""
            field_str = ", ".join(f.fields[:3]) + ("..." if len(f.fields) > 3 else "")
            lines.append(f"  {icon} [{f.from_service}]  {arrow}  [{f.to_service}]{border_note}")
            lines.append(f"     fields: {field_str}")
            lines.append("")

    return "\n".join(lines)
