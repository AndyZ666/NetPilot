#!/usr/bin/env python3
"""Serve the existing ZTP files with an expiring Day-0 publication window."""

import argparse
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, test
import math
import os
from pathlib import Path
import re
import stat
import time


DAY0_PATHS = {"/day0/R6.cfg", "/day0/R7.cfg"}
DAY0_PATH = re.compile(r"/day0/([A-Za-z][A-Za-z0-9_.-]{0,62})\.cfg")


class Day0HTTPRequestHandler(SimpleHTTPRequestHandler):
    def _day0_available(self):
        try:
            name = DAY0_PATH.fullmatch(self.path).group(1)
            directory = Path(self.directory) / "day0"
            if directory.is_symlink():
                return False
            marker = directory / ("." + name + ".expires")
            if not os.path.lexists(marker) and self.path in DAY0_PATHS:
                marker = directory / ".expires"
            descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "r", encoding="ascii") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    return False
                expires = float(handle.read(128))
            return math.isfinite(expires) and 0 < expires - time.time() <= 600
        except (OSError, UnicodeError, ValueError, AttributeError):
            return False

    def send_head(self):
        # Exact paths also reject queries, escaped paths, traversal, and listings.
        # BaseHTTPRequestHandler normalizes a leading // before dispatch.
        day0 = DAY0_PATH.fullmatch(self.path)
        if ((not day0 and self.path != "/R6.cfg")
                or self.requestline.split()[1] != self.path):
            self.send_error(HTTPStatus.NOT_FOUND)
            return None
        if day0 and not self._day0_available():
            self.send_error(HTTPStatus.NOT_FOUND)
            return None
        if not day0:
            return super().send_head()
        # Do not follow a symlink even if a file is replaced after the lease check.
        try:
            descriptor = os.open(Path(self.directory) / "day0" / (day0.group(1) + ".cfg"),
                                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            handle = os.fdopen(descriptor, "rb")
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                handle.close()
                raise OSError("Not a regular configuration file")
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return None
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "application/octet-stream")
        self.send_header("Content-Length", str(metadata.st_size))
        self.send_header("Last-Modified", self.date_time_string(metadata.st_mtime))
        self.end_headers()
        return handle

    def list_directory(self, path):
        self.send_error(HTTPStatus.NOT_FOUND)
        return None

    def end_headers(self):
        if DAY0_PATH.fullmatch(self.path):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int, nargs="?", default=80)
    parser.add_argument("--bind", default="10.250.0.1")
    parser.add_argument("--directory", default="/srv/ztp")
    args = parser.parse_args(argv)
    test(HandlerClass=partial(Day0HTTPRequestHandler, directory=args.directory),
         port=args.port, bind=args.bind)


if __name__ == "__main__":
    main()
