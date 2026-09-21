#!/usr/bin/env python3
from pathlib import Path
import argparse
import sys
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_INVENTORY = BASE_DIR / "inventory" / "devices.yml"
DEFAULT_TEMPLATE_DIR = BASE_DIR / "templates"
DEFAULT_OUTPUT_DIR = BASE_DIR / "generated_configs"


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def render_device(env, inventory, hostname: str) -> str:
    devices = inventory.get("devices", {})
    if hostname not in devices:
        raise KeyError(f"Device '{hostname}' not found in NSOT")

    device = devices[hostname]
    template_path = device.get("template") or inventory["network"]["defaults"]["template"]
    template_name = Path(template_path).name
    template = env.get_template(template_name)

    return template.render(
        device=device,
        network=inventory.get("network", {}),
        routing_domains=inventory.get("routing_domains", {}),
        metadata=inventory.get("metadata", {}),
    ).strip() + "\n"


def main():
    parser = argparse.ArgumentParser(description="Render Arista cEOS configs from the NetPilot NSOT")
    parser.add_argument("device", nargs="?", help="Render one device, e.g. R1. Omit to render all devices.")
    parser.add_argument("--inventory", default=str(DEFAULT_INVENTORY), help="Path to NSOT YAML")
    parser.add_argument("--template-dir", default=str(DEFAULT_TEMPLATE_DIR), help="Jinja2 template directory")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for rendered configs")
    args = parser.parse_args()

    inventory_path = Path(args.inventory).resolve()
    template_dir = Path(args.template_dir).resolve()
    output_dir = Path(args.output_dir).resolve()

    inventory = load_yaml(inventory_path)
    devices = inventory.get("devices", {})
    if not devices:
        raise RuntimeError("No devices found under 'devices:' in the NSOT")

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        undefined=StrictUndefined,
        trim_blocks=False,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )

    targets = [args.device] if args.device else list(devices.keys())
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"NSOT: {inventory_path}")
    print(f"Template directory: {template_dir}")
    print(f"Output directory: {output_dir}")
    print()

    for hostname in targets:
        try:
            rendered = render_device(env, inventory, hostname)
        except Exception as exc:
            print(f"[FAIL] {hostname}: {exc}", file=sys.stderr)
            return 1

        out_file = output_dir / f"{hostname}.cfg"
        out_file.write_text(rendered, encoding="utf-8")
        print(f"[OK] {hostname:3} -> {out_file}")

    print(f"\nRendered {len(targets)} configuration(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
