import json
import tempfile
import unittest
from pathlib import Path

from internet_scanner_blocker import collect, load_config, render


class BlockerTests(unittest.TestCase):
    def test_collect_normalizes_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "cidr"
            folder.mkdir()
            for number in range(50):
                (folder / f"source{number}_v4.txt").write_text("8.8.8.8/32\n" * 20)
            (folder / "ipv6_v6.txt").write_text("2001:4860::1/32\n")
            networks, rows, files = collect(Path(temp))
            self.assertEqual((rows, files), (1001, 51))
            self.assertEqual(networks[4], ["8.8.8.8/32"])
            self.assertEqual(networks[6], ["2001:4860::/32"])

    def test_nft_script_scopes_physical_interfaces(self):
        script = render({4: ["1.2.3.0/24"], 6: ["2001:4860::/32"]}, ["eth0", "eth2"], False)
        self.assertIn('iifname { "eth0", "eth2" } ip saddr @v4 drop', script)
        self.assertIn("hook prerouting priority -150", script)
        self.assertNotIn("flush ruleset", script)
        self.assertNotIn("tailscale0", script)

    def test_config_rejects_tailscale_interface(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps({
                "interfaces": ["tailscale0"], "state_dir": temp,
                "upstream": "https://github.com/OpenFilters/internet-scanners.git",
                "max_change_percent": 25,
            }))
            with self.assertRaises(ValueError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
