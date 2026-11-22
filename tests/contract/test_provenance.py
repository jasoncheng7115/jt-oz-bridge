import hashlib
import json
from pathlib import Path


def test_saved_contract_fixtures_match_recorded_provenance_hashes():
    root = Path("tests/fixtures/contracts")
    manifest = json.loads((root / "manifest.json").read_text())
    assert len({row["path"] for row in manifest["fixtures"]}) == len(manifest["fixtures"])
    for row in manifest["fixtures"]:
        assert (root / row["path"]).parent == root
        assert hashlib.sha256((root / row["path"]).read_bytes()).hexdigest() == row["sha256"]
        assert row["verification"] == "documentation_derived_not_live"
        assert row["source"].startswith("https://")
