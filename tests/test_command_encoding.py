import sys
from computesec import checks


def test_invalid_command_output_does_not_abort_collection(monkeypatch):
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    rc, output = checks.run([sys.executable, "-c", "import os; os.write(1, bytes([255, 10]))"])
    assert rc == 0 and output.endswith("\n")
    assert "\ufffd" in output


def test_flatpak_still_does_not_launch_commands(monkeypatch):
    monkeypatch.setattr(checks, "IN_FLATPAK", True)
    def forbidden(*args, **kwargs):
        raise AssertionError("must not run a process inside Flatpak")
    monkeypatch.setattr(checks.subprocess, "run", forbidden)
    assert checks.run(["lsblk"]) == (None, "")
