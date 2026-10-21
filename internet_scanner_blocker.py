#!/usr/bin/env python3
"""Synchronize OpenFilters CIDRs into an isolated nftables table."""

import argparse
from contextlib import nullcontext
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

TABLE = "internet_scanner_blocker"
NAME = re.compile(r"^[a-zA-Z0-9_.:-]{1,15}$")
FILE = re.compile(r"^[a-z0-9]+_v[46]\.txt$")


def run(argv, **kwargs):
    result = subprocess.run(argv, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{' '.join(argv[:3])}: {result.stderr.strip()}")
    return result


def load_config(path):
    config = json.loads(Path(path).read_text())
    interfaces = config["interfaces"]
    if not isinstance(interfaces, list) or not interfaces or any(
        not isinstance(i, str) or not NAME.fullmatch(i) or i.startswith(("tailscale", "docker", "br-", "veth"))
        for i in interfaces
    ):
        raise ValueError("interfaces must explicitly name external interfaces")
    if len(set(interfaces)) != len(interfaces):
        raise ValueError("duplicate interface")
    config["state_dir"] = Path(config["state_dir"])
    if not 0 <= config["max_change_percent"] <= 100:
        raise ValueError("max_change_percent must be 0..100")
    if config["upstream"] not in ("https://github.com/OpenFilters/internet-scanners", "https://github.com/OpenFilters/internet-scanners.git"):
        raise ValueError("unexpected upstream URL")
    return config


def collect(repo):
    folder = repo / "cidr"
    files = sorted(folder.glob("*.txt"))
    if len(files) < 50 or any(not FILE.fullmatch(p.name) for p in files):
        raise ValueError("unexpected CIDR file set")
    networks = {4: [], 6: []}
    rows = 0
    for path in files:
        family = int(path.stem[-1])
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"{path.name}:{lineno}: {exc}") from exc
            if network.version != family or not network.is_global:
                raise ValueError(f"{path.name}:{lineno}: unexpected address {value}")
            if network.prefixlen < (16 if family == 4 else 24):
                raise ValueError(f"{path.name}:{lineno}: overly broad network {value}")
            networks[family].append(network)
            rows += 1
    if rows < 1000 or rows > 100000:
        raise ValueError(f"unexpected CIDR row count: {rows}")
    return {family: [str(n) for n in ipaddress.collapse_addresses(items)] for family, items in networks.items()}, rows, len(files)


def render(networks, interfaces, replace):
    lines = []
    if replace:
        lines.append(f"delete table inet {TABLE}")
    lines += [
        f"add table inet {TABLE}",
        f"add set inet {TABLE} v4 {{ type ipv4_addr; flags interval; auto-merge; }}",
        f"add set inet {TABLE} v6 {{ type ipv6_addr; flags interval; auto-merge; }}",
        f"add chain inet {TABLE} ingress {{ type filter hook prerouting priority -150; policy accept; }}",
    ]
    names = ", ".join(json.dumps(i) for i in interfaces)
    lines += [
        f"add rule inet {TABLE} ingress iifname {{ {names} }} ip saddr @v4 drop",
        f"add rule inet {TABLE} ingress iifname {{ {names} }} ip6 saddr @v6 drop",
    ]
    for family in (4, 6):
        values = networks[family]
        for start in range(0, len(values), 500):
            lines.append(f"add element inet {TABLE} v{family} {{ {', '.join(values[start:start + 500])} }}")
    return "\n".join(lines) + "\n"


def table_exists():
    result = subprocess.run(["nft", "list", "table", "inet", TABLE], text=True, capture_output=True)
    if result.returncode == 0:
        return True
    if "No such file" in result.stderr:
        return False
    raise RuntimeError(result.stderr.strip())


def snapshot(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as out:
        json.dump(data, out, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
        temporary = out.name
    os.replace(temporary, path)


def atomic_text(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
        temporary = out.name
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/internet-scanner-blocker.json")
    parser.add_argument("--apply", action="store_true", help="apply to the local nftables ruleset")
    parser.add_argument("--accept-large-change", action="store_true", help="override the CIDR change guard")
    parser.add_argument("--from-dir", type=Path, help="use an existing checkout for offline review")
    args = parser.parse_args()
    config = load_config(args.config)
    state = config["state_dir"]
    if args.apply:
        state.mkdir(parents=True, exist_ok=True)
    context = (state / "lock").open("w") if args.apply else nullcontext()
    with context as lock:
        if lock is not None:
            fcntl.flock(lock, fcntl.LOCK_EX)
        with tempfile.TemporaryDirectory() as temp:
            repo = args.from_dir
            if repo is None:
                repo = Path(temp) / "upstream"
                run(["git", "clone", "--depth", "1", "--quiet", config["upstream"], str(repo)], timeout=120)
            commit = run(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.strip()
            networks, rows, files = collect(repo)
        previous_path = state / "last-applied.json"
        previous = json.loads(previous_path.read_text()) if previous_path.exists() else None
        current = set(networks[4] + networks[6])
        old = set(previous["v4"] + previous["v6"]) if previous else set()
        added, removed = current - old, old - current
        print(f"commit={commit} files={files} rows={rows} cidrs={len(current)} added={len(added)} removed={len(removed)}")
        exists = table_exists() if args.apply else False
        if previous and previous["commit"] == commit and not added and not removed and previous["interfaces"] == config["interfaces"] and (not args.apply or (exists and (state / "active.nft").exists())):
            print("unchanged")
            return
        if previous and len(added) + len(removed) > max(100, len(old) * config["max_change_percent"] / 100) and not args.accept_large_change:
            raise ValueError("CIDR change exceeds configured limit; review before applying")
        nft_text = render(networks, config["interfaces"], replace=exists)
        if not args.apply:
            print("add sample:", ", ".join(sorted(added)[:5]))
            print("remove sample:", ", ".join(sorted(removed)[:5]))
            print("dry run; no firewall changes")
            return
        with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as out:
            out.write(nft_text)
            script = Path(out.name)
        try:
            run(["nft", "-c", "-f", str(script)])
            run(["nft", "-f", str(script)])
        finally:
            script.unlink(missing_ok=True)
        atomic_text(state / "active.nft", render(networks, config["interfaces"], replace=False))
        snapshot(previous_path, {"commit": commit, "v4": networks[4], "v6": networks[6], "interfaces": config["interfaces"]})
        print("applied")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, subprocess.CalledProcessError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
