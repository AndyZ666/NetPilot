"""Concurrent GUI operations must not expose protected transport logs."""

import io
import logging
import sys
import threading
import unittest

from security.setup_recovery_accounts import quiet_transport


class QuietTransportLogging(unittest.TestCase):
    def setUp(self):
        original = logging.root.manager.disable
        self.addCleanup(logging.disable, original)
        logging.disable(logging.NOTSET)

    def test_nested_contexts_restore_the_original_logging_threshold(self):
        logging.disable(logging.WARNING)
        with quiet_transport():
            self.assertEqual(logging.root.manager.disable, sys.maxsize)
            with quiet_transport():
                self.assertEqual(logging.root.manager.disable, sys.maxsize)
            self.assertEqual(logging.root.manager.disable, sys.maxsize)
        self.assertEqual(logging.root.manager.disable, logging.WARNING)

    def test_overlapping_threads_cannot_restore_logging_during_another_transport(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("netmiko.transport-log-test")
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        first_entered, second_started, second_entered = (threading.Event() for _ in range(3))
        release_first, release_second = threading.Event(), threading.Event()

        def first():
            with quiet_transport():
                first_entered.set()
                release_first.wait(5)
                logger.error("first synthetic protected configuration")

        def second():
            second_started.set()
            with quiet_transport():
                second_entered.set()
                release_second.wait(5)
                logger.error("second synthetic protected configuration")

        one, two = threading.Thread(target=first), threading.Thread(target=second)
        try:
            one.start()
            self.assertTrue(first_entered.wait(2))
            two.start()
            self.assertTrue(second_started.wait(2))
            self.assertFalse(second_entered.wait(0.1), "Second transport entered before first released the global logging guard")
            self.assertEqual(logging.root.manager.disable, sys.maxsize)
            release_first.set()
            self.assertTrue(second_entered.wait(2))
            one.join(2)
            self.assertFalse(one.is_alive())
            self.assertEqual(logging.root.manager.disable, sys.maxsize)
            release_second.set()
        finally:
            release_first.set()
            release_second.set()
            if one.ident is not None:
                one.join(2)
            if two.ident is not None:
                two.join(2)
        self.assertFalse(one.is_alive())
        self.assertFalse(two.is_alive())
        self.assertEqual(stream.getvalue(), "")
        self.assertEqual(logging.root.manager.disable, logging.NOTSET)


if __name__ == "__main__":
    unittest.main()
