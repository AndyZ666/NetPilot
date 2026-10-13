"""Offline checks for the scheduled rotation user-unit wiring."""

import configparser
from pathlib import Path
import unittest


UNIT_DIRECTORY = Path(__file__).resolve().parents[1] / "security" / "systemd"


def read_unit(name):
    unit = configparser.ConfigParser(interpolation=None, strict=False)
    unit.optionxform = str
    unit.read(UNIT_DIRECTORY / name)
    return unit


class RotationSystemdTests(unittest.TestCase):
    def test_daily_persistent_timer_invokes_due_guard(self):
        timer = read_unit("netpilot-rotation.timer")
        self.assertEqual(timer["Timer"]["OnCalendar"], "*-*-* 09:00:00")
        self.assertEqual(timer["Timer"]["Persistent"], "true")
        self.assertEqual(timer["Timer"]["Unit"], "netpilot-rotation.service")
        self.assertEqual(timer["Install"]["WantedBy"], "timers.target")

    def test_runner_is_noninteractive_and_cannot_restart_automatically(self):
        service = read_unit("netpilot-rotation.service")
        options = service["Service"]
        self.assertEqual(options["Type"], "oneshot")
        self.assertEqual(options["WorkingDirectory"], "%h/Documents/NetPilot")
        self.assertEqual(
            options["ExecStart"],
            "%h/Documents/NetPilot/.venv/bin/python -B -m security.rotation_scheduler run --execute",
        )
        self.assertEqual(options["Restart"], "no")
        self.assertEqual(options["TimeoutStartSec"], "0")
        self.assertNotIn("Wants", service["Unit"])
        self.assertNotIn("Requires", service["Unit"])
        self.assertNotIn("ExecStartPre", options)
        self.assertNotIn("ExecStartPost", options)

    def test_private_runtime_outputs_and_no_inline_secret_values(self):
        options = read_unit("netpilot-rotation.service")["Service"]
        self.assertEqual(options["UMask"], "0077")
        self.assertEqual(options["NoNewPrivileges"], "yes")
        self.assertEqual(options["LimitCORE"], "0")
        text = (UNIT_DIRECTORY / "netpilot-rotation.service").read_text()
        for line in text.splitlines():
            if line.startswith("Environment="):
                self.assertFalse(any(key in line for key in (
                    "PASSWORD", "TOKEN", "SMTP_USERNAME", "SMTP_FROM", "SMTP_TO",
                )))


if __name__ == "__main__":
    unittest.main()
