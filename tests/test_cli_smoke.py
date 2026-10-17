"""
The CLI is the product most people will actually touch, and until now nothing
exercised its argument parser.

That gap was not theoretical: a duplicated `-n` flag made argparse raise at
import time, so EVERY subcommand died -- while 137 tests stayed green, because
they all import modules rather than building the parser. The whole tool was
unusable and the suite said nothing.

One line of setup, and it would have caught it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tool_judge.cli import build_parser, main          # noqa: E402


def test_parser_builds():
    """Catches duplicate flags and malformed subcommands at import time."""
    build_parser()


@pytest.mark.parametrize("argv", [
    ["check", "ls", "-la"],
    ["list"],
    ["posture"],
    ["posture", "--mode", "allow-silent"],
    ["cut-off"],
    ["cut-off", "--reset"],
    ["pending"],
    ["log"],
    ["log", "-n", "5"],
    ["grant", "task:t1", "ls:*", "allow"],
    ["revoke", "task:t1", "ls:*"],
    ["decide", "1"],
    ["decide", "1", "--refuse"],
    ["device", "list"],
    ["profile", "list"],
    ["compile"],
])
def test_every_documented_command_parses(argv):
    build_parser().parse_args(argv)


def test_cut_off_refuses_a_granted_command(tmp_path, capsys):
    """The switch, through the real entry point rather than the library."""
    store = str(tmp_path / "s.db")
    assert main(["--store", store, "cut-off", "--reason", "test",
                 "--by", "pytest"]) == 0
    # A command the rails allow must still be refused while cut off.
    rc = main(["--store", store, "--rails",
               str(ROOT / "rails" / "g1-ble-backend.yaml"),
               "--task", "t1", "check", "git", "status"])
    assert rc == 3, f"cut off should refuse everything, got exit {rc}"
    assert "CUT OFF" in capsys.readouterr().err


def test_reset_lifts_the_switch(tmp_path):
    store = str(tmp_path / "s.db")
    main(["--store", store, "cut-off", "--reason", "test"])
    main(["--store", store, "cut-off", "--reset"])
    assert main(["--store", store, "--rails",
                 str(ROOT / "rails" / "g1-ble-backend.yaml"),
                 "--task", "t1", "check", "git", "status"]) == 0
