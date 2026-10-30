"""Offline request handling; no HTTP sockets or live ZTP servers are started."""

import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[1] / "lab8" / "ztp-server" / "http_server.py"
SPEC = importlib.util.spec_from_file_location("netpilot_ztp_http", SOURCE)
http = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(http)


class ZtpHttpTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="netpilot-ztp-http-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.day0 = self.root / "day0"
        self.day0.mkdir()
        self.expiry = self.day0 / ".expires"
        for name in ("R6", "R7"):
            (self.day0 / f"{name}.cfg").write_text(f"hostname {name}\n! synthetic fixture\n")
        (self.root / "R6.cfg").write_text("hostname R6\n! original public PoC\n")
        self.enterContext(patch.object(http.time, "time", return_value=1000.0))
        self.enterContext(patch("socket.socket", side_effect=AssertionError("Network access forbidden")))

    def handler(self, path, command="GET"):
        handler = object.__new__(http.Day0HTTPRequestHandler)
        handler.directory = str(self.root)
        handler.path = path
        handler.command = command
        handler.requestline = f"{command} {path} HTTP/1.1"
        handler.headers = {}
        handler.wfile = io.BytesIO()
        handler.send_error = Mock()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        return handler

    def test_valid_window_serves_both_device_configs_without_network_calls(self):
        self.expiry.write_text("1300.0")
        for name in ("R6", "R7"):
            with self.subTest(name=name):
                handler = self.handler(f"/day0/{name}.cfg")
                handler.do_GET()
                self.assertEqual(handler.wfile.getvalue(), (self.day0 / f"{name}.cfg").read_bytes())
                handler.send_response.assert_called_once_with(200)
                handler.send_error.assert_not_called()

    def test_missing_malformed_expired_or_unreasonably_future_window_fails_closed(self):
        for value in (None, "", "broken", "nan", "inf", "-inf", "-1", "999.9", "1000", "1600.1"):
            for method in ("GET", "HEAD"):
                with self.subTest(expiry=value, method=method):
                    self.expiry.unlink(missing_ok=True)
                    if value is not None:
                        self.expiry.write_text(value)
                    handler = self.handler("/day0/R6.cfg", method)
                    getattr(handler, "do_" + method)()
                    handler.send_error.assert_called_once_with(404)
                    handler.send_response.assert_not_called()
                    self.assertEqual(handler.wfile.getvalue(), b"")

    def test_exact_expiry_boundary_and_ten_minute_maximum_are_enforced(self):
        for expiry, allowed in ((1000, False), (1000.01, True), (1600, True), (1600.01, False)):
            with self.subTest(expiry=expiry):
                self.expiry.write_text(str(expiry))
                handler = self.handler("/day0/R7.cfg")
                self.assertIs(handler._day0_available(), allowed)

    def test_get_and_head_recheck_expiry_after_an_earlier_success(self):
        self.expiry.write_text("1300")
        handler = self.handler("/day0/R6.cfg", "HEAD")
        handler.do_HEAD()
        handler.send_response.assert_called_once_with(200)
        self.assertEqual(handler.wfile.getvalue(), b"")
        with patch.object(http.time, "time", return_value=1300):
            for method in ("GET", "HEAD"):
                expired = self.handler("/day0/R6.cfg", method)
                getattr(expired, "do_" + method)()
                expired.send_error.assert_called_once_with(404)
                expired.send_response.assert_not_called()

    def test_removing_publication_marker_stops_serving_retained_files(self):
        self.expiry.write_text("1300")
        self.expiry.unlink()
        handler = self.handler("/day0/R7.cfg")
        handler.do_GET()
        handler.send_error.assert_called_once_with(404)
        self.assertTrue((self.day0 / "R7.cfg").exists())
        self.assertEqual(handler.wfile.getvalue(), b"")

    def test_directory_listing_marker_and_all_path_variants_are_denied(self):
        self.expiry.write_text("1300")
        for path in ("/", "/day0", "/day0/", "/day0/.expires", "/day0/R8.cfg",
                     "/day0/R6.cfg?download", "/day0/R6.cfg/", "/day0//R6.cfg",
                     "//day0/R6.cfg", "/%64ay0/R6.cfg", "/day0/%52%36.cfg",
                     "/day0/../R6.cfg", "/day0/../day0/R6.cfg", "/./day0/R6.cfg",
                     "/R6.cfg?download", "/private/R6.cfg"):
            with self.subTest(path=path):
                handler = self.handler(path)
                handler.do_GET()
                handler.send_error.assert_called_once_with(404)
                handler.send_response.assert_not_called()
                self.assertEqual(handler.wfile.getvalue(), b"")

    def test_original_public_poc_remains_available_without_a_window(self):
        handler = self.handler("/R6.cfg")
        handler.do_GET()
        self.assertEqual(handler.wfile.getvalue(), (self.root / "R6.cfg").read_bytes())
        handler.send_response.assert_called_once_with(200)
        handler.send_error.assert_not_called()

    def test_request_target_normalization_does_not_bypass_exact_path_check(self):
        self.expiry.write_text("1300")
        handler = self.handler("/day0/R6.cfg")
        handler.requestline = "GET //day0/R6.cfg HTTP/1.1"
        handler.do_GET()
        handler.send_error.assert_called_once_with(404)
        handler.send_response.assert_not_called()

    def test_missing_config_fails_closed_even_with_valid_window(self):
        self.expiry.write_text("1300")
        (self.day0 / "R6.cfg").unlink()
        handler = self.handler("/day0/R6.cfg")
        handler.do_GET()
        self.assertEqual(handler.send_error.call_args.args[0], 404)
        self.assertEqual(handler.wfile.getvalue(), b"")

    def test_day0_responses_disable_http_caching(self):
        for path in ("/day0/R6.cfg", "/day0/R7.cfg"):
            with self.subTest(path=path):
                handler = self.handler(path)
                with patch.object(http.SimpleHTTPRequestHandler, "end_headers") as finish:
                    http.Day0HTTPRequestHandler.end_headers(handler)
                handler.send_header.assert_called_once_with("Cache-Control", "no-store")
                finish.assert_called_once_with()

    def test_command_line_keeps_bootstrap_bind_port_and_document_root(self):
        with patch.object(http, "test") as serve:
            http.main(["80", "--bind", "10.250.0.1", "--directory", "/srv/ztp"])
        arguments = serve.call_args.kwargs
        self.assertEqual(arguments["port"], 80)
        self.assertEqual(arguments["bind"], "10.250.0.1")
        self.assertIs(arguments["HandlerClass"].func, http.Day0HTTPRequestHandler)
        self.assertEqual(arguments["HandlerClass"].keywords, {"directory": "/srv/ztp"})

    def test_new_devices_require_their_own_lease_and_expire_independently(self):
        self.expiry.write_text("1300")
        for name in ("R8", "R9"):
            (self.day0 / (name + ".cfg")).write_text("hostname " + name)
        # The legacy pair lease cannot authorize any newly named device.
        denied = self.handler("/day0/R8.cfg")
        denied.do_GET()
        denied.send_error.assert_called_once_with(404)
        (self.day0 / ".R8.expires").write_text("1060")
        (self.day0 / ".R9.expires").write_text("1300")
        for name in ("R8", "R9"):
            handler = self.handler("/day0/" + name + ".cfg")
            handler.do_GET()
            handler.send_response.assert_called_once_with(200)
            self.assertEqual(handler.wfile.getvalue(), ("hostname " + name).encode())
        with patch.object(http.time, "time", return_value=1060):
            expired = self.handler("/day0/R8.cfg")
            expired.do_HEAD()
            expired.send_error.assert_called_once_with(404)
            active = self.handler("/day0/R9.cfg")
            active.do_HEAD()
            active.send_response.assert_called_once_with(200)

    def test_symlinked_lease_or_configuration_is_never_served(self):
        self.expiry.write_text("1300")
        unrelated = self.root / "unrelated"
        unrelated.write_text("1300")
        marker = self.day0 / ".R6.expires"
        marker.symlink_to(unrelated)
        handler = self.handler("/day0/R6.cfg")
        handler.do_GET()
        handler.send_error.assert_called_once_with(404)
        marker.unlink()
        config = self.day0 / "R6.cfg"
        config.unlink()
        config.symlink_to(unrelated)
        handler = self.handler("/day0/R6.cfg")
        handler.do_GET()
        handler.send_error.assert_called_once_with(404)
        self.assertEqual(handler.wfile.getvalue(), b"")


if __name__ == "__main__":
    unittest.main()
