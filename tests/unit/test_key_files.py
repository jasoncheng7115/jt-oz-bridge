import base64
import os

import pytest
from pydantic import SecretStr

from jt_oz_bridge.security.cipher import decode_key
from jt_oz_bridge.security.key_files import generate_key_file


def test_explicit_generation_is_private_valid_and_never_overwrites(tmp_path):
    tmp_path.chmod(0o700)
    target = tmp_path / "master.key"
    generate_key_file(target)
    original = target.read_bytes()
    assert len(decode_key(SecretStr(original.decode().strip()))) == 32
    assert target.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        generate_key_file(target)
    assert target.read_bytes() == original
    link = tmp_path / "link.key"
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        generate_key_file(link)
    assert target.read_bytes() == original


def test_key_creation_refuses_shared_parent_and_relative_path(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(ValueError):
        generate_key_file(tmp_path / "key")
    assert not (tmp_path / "key").exists()
    with pytest.raises(ValueError):
        generate_key_file(__import__("pathlib").Path("relative.key"))


def test_cli_validation_remains_secret_free_and_generation_does_not_print_key(
    tmp_path, monkeypatch, capsys
):
    from jt_oz_bridge.cli import main

    monkeypatch.delenv("JTOZ_SECRET_KEY", raising=False)
    monkeypatch.setattr("sys.argv", ["jt-oz-bridge", "validate"])
    main()
    assert "Configuration valid" in capsys.readouterr().out
    tmp_path.chmod(0o700)
    target = tmp_path / "key"
    previous = os.umask(0o077)
    try:
        monkeypatch.setattr(
            "sys.argv", ["jt-oz-bridge", "generate-key", "--secret-output", str(target)]
        )
        main()
        output = capsys.readouterr()
        assert target.read_text().strip() not in output.out + output.err
        assert len(base64.b64decode(target.read_bytes())) == 32
    finally:
        os.umask(previous)
