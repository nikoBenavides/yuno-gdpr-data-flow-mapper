#!/usr/bin/env python3
"""
Yuno GDPR Data Flow Mapper — CLI entry point

Usage:
  python main.py analyze --input services.json
  python main.py analyze --input services.json --rules rules.yaml --output-dir reports/
  python main.py dsar --input services.json --customer-id cust_123
  python main.py visualize --input services.json --format dot
"""

import argparse
import json
import sys
from pathlib import Path

from analyzer.loader import load_services
from analyzer.engine import run_compliance_checks, build_data_flows
from analyzer.reporter import (
    generate_inventory_markdown,
    generate_inventory_json,
    generate_risk_report_markdown,
    generate_dsar_response,
)
from analyzer.visualizer import generate_dot, generate_ascii_lineage
from analyzer.models import Severity


def cmd_analyze(args):
    print(f"[*] Loading services from {args.input}...")
    services = load_services(args.input)
    print(f"[*] Loaded {len(services)} services.")

    extra_rules = []
    if args.rules:
        from analyzer.policy_loader import load_yaml_rules
        extra_rules = load_yaml_rules(args.rules)
        print(f"[*] Loaded {len(extra_rules)} custom rules from {args.rules}.")

    print("[*] Running compliance checks...")
    violations = run_compliance_checks(services, extra_rules)
    flows = build_data_flows(services)

    critical = sum(1 for v in violations if v.severity == Severity.CRITICAL)
    high = sum(1 for v in violations if v.severity == Severity.HIGH)
    medium = sum(1 for v in violations if v.severity == Severity.MEDIUM)

    print(f"\n{'='*60}")
    print(f"  COMPLIANCE SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"  Total findings : {len(violations)}")
    print(f"  🔴 Critical     : {critical}")
    print(f"  🟠 High         : {high}")
    print(f"  🟡 Medium       : {medium}")
    print(f"  Cross-border flows : {sum(1 for f in flows if f.crosses_border)}")
    print(f"{'='*60}\n")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Data Processing Inventory
    inventory_md = generate_inventory_markdown(services)
    inventory_json = generate_inventory_json(services)
    (out_dir / "data_processing_inventory.md").write_text(inventory_md)
    (out_dir / "data_processing_inventory.json").write_text(
        json.dumps(inventory_json, indent=2)
    )
    print(f"[✓] Data Processing Inventory → {out_dir}/data_processing_inventory.md")

    # Compliance Risk Report
    risk_report = generate_risk_report_markdown(violations, flows)
    (out_dir / "compliance_risk_report.md").write_text(risk_report)
    print(f"[✓] Compliance Risk Report     → {out_dir}/compliance_risk_report.md")

    # ASCII lineage
    ascii_art = generate_ascii_lineage(flows)
    (out_dir / "data_lineage.txt").write_text(ascii_art)
    print(f"[✓] Data Lineage (ASCII)       → {out_dir}/data_lineage.txt")

    # DOT graph
    regions = {svc.service_id: svc.region for svc in services}
    dot_graph = generate_dot(flows, regions)
    (out_dir / "data_lineage.dot").write_text(dot_graph)
    print(f"[✓] Data Lineage (DOT/Graphviz)→ {out_dir}/data_lineage.dot")
    print(f"    (render with: dot -Tpng {out_dir}/data_lineage.dot -o {out_dir}/data_lineage.png)")

    if critical > 0:
        print(f"\n⛔  {critical} CRITICAL finding(s) require immediate attention.")
        sys.exit(1)


def cmd_dsar(args):
    services = load_services(args.input)
    response = generate_dsar_response(services, args.customer_id)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"dsar_{args.customer_id}.md"
    out_path.write_text(response)
    print(response)
    print(f"\n[✓] DSAR report written to {out_path}")


def cmd_visualize(args):
    services = load_services(args.input)
    flows = build_data_flows(services)
    regions = {svc.service_id: svc.region for svc in services}
    if args.format == "dot":
        print(generate_dot(flows, regions))
    else:
        print(generate_ascii_lineage(flows))


def main():
    parser = argparse.ArgumentParser(
        description="Yuno GDPR Data Flow Mapper — cardholder data & PII compliance tool"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # analyze
    p_analyze = sub.add_parser("analyze", help="Run full GDPR/PCI compliance analysis")
    p_analyze.add_argument("--input", default="services.json", help="Path to services.json")
    p_analyze.add_argument("--rules", help="Optional YAML policy-as-code rules file")
    p_analyze.add_argument("--output-dir", default="reports", help="Output directory for reports")

    # dsar
    p_dsar = sub.add_parser("dsar", help="Simulate a GDPR Data Subject Access Request")
    p_dsar.add_argument("--input", default="services.json")
    p_dsar.add_argument("--customer-id", required=True)
    p_dsar.add_argument("--output-dir", default="reports")

    # visualize
    p_vis = sub.add_parser("visualize", help="Print data flow graph")
    p_vis.add_argument("--input", default="services.json")
    p_vis.add_argument("--format", choices=["dot", "ascii"], default="ascii")

    args = parser.parse_args()
    dispatch = {"analyze": cmd_analyze, "dsar": cmd_dsar, "visualize": cmd_visualize}
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
