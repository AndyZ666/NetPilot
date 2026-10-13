"""Offline synthetic Vault verification tests; no token, network, or device access."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
import unittest
from unittest.mock import patch

from security import credential_provider, rotation_adapters
from security import test_vault_write_live as verifier


CURRENT_ID = "a" * 26
PENDING_ID = "b" * 26
TEST_ID = "c" * 26
FIRST = "fixture-first-synthetic-secret-not-a-device-password"
SECOND = "fixture-second-synthetic-secret-not-a-device-password"
EXISTING = "fixture-existing-secret-not-a-device-password"
PRIVATE_ERROR = "fixture-private-cli-error"


def item(reference, title, password=EXISTING):
    return {
        "id": reference, "title": title, "category": "LOGIN",
        "fields": [
            {"id": "username", "label": "username", "type": "STRING", "value": "fixture-existing-user"},
            {"id": "password", "label": "password", "type": "CONCEALED", "value": password},
        ],
        "notesPlain": "Keep this existing metadata", "tags": ["fixture-tag"],
    }


class FakeVault:
    def __init__(self):
        self.items = {
            CURRENT_ID: item(CURRENT_ID, "NetPilot-Current"),
            PENDING_ID: item(PENDING_ID, "NetPilot-Pending"),
        }
        self.calls = []
        self.writes = []
        self.before = lambda arguments, payload: None
        self.after = lambda arguments, payload, result: result
        self.ignore_edit = False

    def __call__(self, arguments, *, input_text=None):
        arguments = list(arguments)
        self.calls.append((arguments, input_text))
        self.before(arguments, input_text)
        operation = arguments[1]
        if operation == "list":
            result = [{"id": value["id"], "title": value["title"]} for value in self.items.values()]
        elif operation == "get":
            result = deepcopy(self.items[arguments[2]])
        elif operation == "template":
            result = item(None, "Login", "")
            result.pop("id")
            result["fields"][0]["value"] = ""
        elif operation == "create":
            result = json.loads(input_text)
            result["id"] = TEST_ID
            self.items[TEST_ID] = deepcopy(result)
            self.writes.append((operation, TEST_ID))
        elif operation == "edit":
            reference = arguments[2]
            result = json.loads(input_text)
            if not self.ignore_edit:
                self.items[reference] = deepcopy(result)
            self.writes.append((operation, reference))
        else:
            raise AssertionError("Unexpected CLI operation")
        return json.dumps(self.after(arguments, input_text, result))


class VaultWriteLiveTests(unittest.TestCase):
    def setUp(self):
        self.vault = FakeVault()
        self.production = deepcopy(self.vault.items)
        self.cli = self.start_patch(credential_provider, "_run_op", side_effect=self.vault)
        self.token = self.start_patch(credential_provider, "_read_token", side_effect=AssertionError("Token access forbidden"))
        self.connect = self.start_patch(rotation_adapters, "ConnectHandler", side_effect=AssertionError("Device access forbidden"))
        self.credentials = self.start_patch(credential_provider, "get_credentials", side_effect=AssertionError("Production credential access forbidden"))
        self.generated = self.start_patch(verifier.secrets, "token_urlsafe", side_effect=[FIRST, SECOND])
        self.tty = self.start_patch(verifier.sys.stdin, "isatty", return_value=True)

    def start_patch(self, target, name, **kwargs):
        patcher = patch.object(target, name, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def run_verifier(self, arguments=None, answers=None):
        output = io.StringIO()
        if arguments is None:
            arguments = ["--execute"]
        if answers is None:
            answers = [verifier.CONFIRMATION]
        with patch("builtins.input", side_effect=answers) as prompt, redirect_stdout(output), redirect_stderr(output):
            result = verifier.main(arguments)
        self.token.assert_not_called()
        self.connect.assert_not_called()
        self.credentials.assert_not_called()
        for reference, original in self.production.items():
            self.assertEqual(self.vault.items[reference], original)
        text = output.getvalue()
        for secret in (FIRST, SECOND, EXISTING, PRIVATE_ERROR):
            self.assertNotIn(secret, text)
        for line in text.splitlines():
            self.assertTrue(line.startswith(("PASS |", "FAIL |")), line)
        for args, payload in self.vault.calls:
            self.assertEqual(args[0], "item")
            self.assertIn(args[1], ("list", "get", "template", "create", "edit"))
            for secret in (FIRST, SECOND, EXISTING):
                self.assertNotIn(secret, repr(args))
            if args[1] != "template":
                self.assertEqual(args[args.index("--vault") + 1], "NetPilot-Secrets")
            if args[1] in ("get", "edit"):
                self.assertNotIn(args[2], (CURRENT_ID, PENDING_ID, "NetPilot-Current", "NetPilot-Pending"))
            if args[1] in ("create", "edit"):
                self.assertIsInstance(payload, str)
                self.assertEqual(json.loads(payload)["title"], verifier.TITLE)
                self.assertNotIn("--template", args)
                if args[1] == "create":
                    self.assertEqual(args[2], "-")
            else:
                self.assertIsNone(payload)
        return result, text, prompt

    def existing(self):
        self.vault.items[TEST_ID] = item(TEST_ID, verifier.TITLE)
        return self.vault.items[TEST_ID]

    def test_default_and_explicit_dry_run_are_completely_offline(self):
        for arguments in ([], ["--dry-run"]):
            with self.subTest(arguments=arguments):
                result, _, prompt = self.run_verifier(arguments)
                self.assertEqual(result, 0)
                prompt.assert_not_called()
        self.cli.assert_not_called()
        self.generated.assert_not_called()

    def test_conflicting_or_incomplete_execution_flags_fail_before_vault(self):
        for arguments in (["--execute", "--dry-run"], ["--overwrite-existing"]):
            with self.subTest(arguments=arguments):
                result, _, _ = self.run_verifier(arguments)
                self.assertEqual(result, 1)
        self.cli.assert_not_called()
        self.generated.assert_not_called()

    def test_execute_requires_a_terminal_and_exact_confirmation(self):
        self.tty.return_value = False
        result, _, prompt = self.run_verifier()
        self.assertEqual(result, 1)
        prompt.assert_not_called()
        self.tty.return_value = True
        result, _, _ = self.run_verifier(answers=[verifier.CONFIRMATION.lower()])
        self.assertEqual(result, 1)
        self.cli.assert_not_called()

    def test_interrupt_at_confirmation_is_sanitized_and_offline(self):
        result, _, _ = self.run_verifier(answers=KeyboardInterrupt())
        self.assertEqual(result, 130)
        self.cli.assert_not_called()

    def test_wrong_vault_or_disabled_secure_writes_fail_before_any_cli_call(self):
        for target, attribute, value in (
                (credential_provider, "VAULT", "Other-Vault"),
                (rotation_adapters.OnePasswordStore, "live_writes_supported", False),
                (rotation_adapters.OnePasswordStore, "live_writes_supported", 1)):
            with self.subTest(attribute=attribute, value=value), patch.object(target, attribute, value):
                result, _, _ = self.run_verifier()
                self.assertEqual(result, 1)
        self.cli.assert_not_called()

    def test_create_then_update_require_separate_cli_readbacks(self):
        result, text, _ = self.run_verifier()
        self.assertEqual(result, 0)
        self.assertEqual(self.vault.writes, [("create", TEST_ID), ("edit", TEST_ID)])
        operations = [arguments[1] for arguments, _ in self.vault.calls]
        create_index, edit_index = operations.index("create"), operations.index("edit")
        self.assertIn("get", operations[create_index + 1:edit_index])
        self.assertIn("get", operations[edit_index + 1:])
        self.assertEqual([call.args for call in self.generated.call_args_list], [(32,), (32,)])
        fields = self.vault.items[TEST_ID]["fields"]
        self.assertEqual(fields[0]["value"], verifier.USERNAME)
        self.assertEqual(fields[1]["value"], SECOND)
        self.assertIn("retained", text)
        self.assertNotIn("FAIL", text)

    def test_existing_item_is_not_read_or_overwritten_without_explicit_flag(self):
        original = deepcopy(self.existing())
        result, _, prompt = self.run_verifier()
        self.assertEqual(result, 1)
        self.assertEqual(prompt.call_count, 1)
        self.assertEqual(self.vault.items[TEST_ID], original)
        self.assertFalse(self.vault.writes)
        self.assertFalse(any(arguments[1] == "get" for arguments, _ in self.vault.calls))
        self.generated.assert_not_called()

    def test_existing_flag_alone_does_not_authorize_overwrite(self):
        original = deepcopy(self.existing())
        result, _, _ = self.run_verifier(["--execute", "--overwrite-existing"],
                                         [verifier.CONFIRMATION, verifier.CONFIRMATION])
        self.assertEqual(result, 1)
        self.assertEqual(self.vault.items[TEST_ID], original)
        self.assertFalse(self.vault.writes)
        self.generated.assert_not_called()

    def test_approved_existing_item_updates_preserve_metadata(self):
        original = deepcopy(self.existing())
        result, _, prompt = self.run_verifier(["--execute", "--overwrite-existing"],
                                              [verifier.CONFIRMATION, verifier.OVERWRITE_CONFIRMATION])
        self.assertEqual(result, 0)
        self.assertEqual(prompt.call_count, 2)
        self.assertEqual(self.vault.writes, [("edit", TEST_ID), ("edit", TEST_ID)])
        for name in ("notesPlain", "tags", "category", "id", "title"):
            self.assertEqual(self.vault.items[TEST_ID][name], original[name])

    def test_concurrent_change_during_existing_approval_blocks_edit(self):
        self.existing()
        def answer(prompt):
            if "OVERWRITE " in prompt:
                self.vault.items[TEST_ID]["notesPlain"] = "Another writer changed this item"
                return verifier.OVERWRITE_CONFIRMATION
            return verifier.CONFIRMATION
        result, _, _ = self.run_verifier(["--execute", "--overwrite-existing"], answer)
        self.assertEqual(result, 1)
        self.assertFalse(self.vault.writes)

    def test_duplicate_test_titles_fail_without_any_write(self):
        self.existing()
        self.vault.items["d" * 26] = item("d" * 26, verifier.TITLE)
        result, _, _ = self.run_verifier()
        self.assertEqual(result, 1)
        self.assertFalse(self.vault.writes)

    def test_test_item_appearing_before_create_is_not_overwritten(self):
        def after(arguments, payload, result):
            if arguments[1] == "template":
                self.existing()
            return result
        self.vault.after = after
        result, _, _ = self.run_verifier()
        self.assertEqual(result, 1)
        self.assertFalse(self.vault.writes)

    def test_duplicate_generated_passwords_fail_before_writes(self):
        self.generated.side_effect = [FIRST, FIRST]
        result, _, _ = self.run_verifier()
        self.assertEqual(result, 1)
        self.assertFalse(self.vault.writes)

    def test_unsupported_json_stdin_has_no_secret_argv_or_file_fallback(self):
        def before(arguments, payload):
            if arguments[1] == "create":
                raise RuntimeError(FIRST + PRIVATE_ERROR)
        self.vault.before = before
        with patch("pathlib.Path.write_text", side_effect=AssertionError("Secret file forbidden")) as write_text, \
                patch("pathlib.Path.write_bytes", side_effect=AssertionError("Secret file forbidden")) as write_bytes:
            result, _, _ = self.run_verifier()
        self.assertEqual(result, 1)
        self.assertEqual(sum(arguments[1] in ("create", "edit") for arguments, _ in self.vault.calls), 1)
        self.assertFalse(self.vault.writes)
        write_text.assert_not_called()
        write_bytes.assert_not_called()

    def test_unknown_create_outcome_stops_without_retry_or_delete(self):
        def after(arguments, payload, result):
            if arguments[1] == "create":
                raise RuntimeError(FIRST + PRIVATE_ERROR)
            return result
        self.vault.after = after
        result, _, _ = self.run_verifier()
        self.assertEqual(result, 1)
        self.assertEqual(self.vault.writes, [("create", TEST_ID)])
        self.assertIn(TEST_ID, self.vault.items)

    def test_unknown_edit_outcome_stops_without_retry_or_delete(self):
        def after(arguments, payload, result):
            if arguments[1] == "edit":
                raise RuntimeError(SECOND + PRIVATE_ERROR)
            return result
        self.vault.after = after
        result, _, _ = self.run_verifier()
        self.assertEqual(result, 1)
        self.assertEqual(self.vault.writes, [("create", TEST_ID), ("edit", TEST_ID)])
        self.assertIn(TEST_ID, self.vault.items)

    def test_failed_initial_readback_prevents_update(self):
        def after(arguments, payload, result):
            if arguments[1] == "create":
                self.vault.items[TEST_ID]["fields"][1]["value"] = EXISTING
            return result
        self.vault.after = after
        result, _, _ = self.run_verifier()
        self.assertEqual(result, 1)
        self.assertEqual(self.vault.writes, [("create", TEST_ID)])

    def test_successful_edit_response_does_not_replace_independent_readback(self):
        self.vault.ignore_edit = True
        result, text, _ = self.run_verifier()
        self.assertEqual(result, 1)
        self.assertIn("PASS | initial", text)
        self.assertNotIn("PASS | update", text)

    def test_readback_username_mismatch_prevents_update(self):
        def after(arguments, payload, result):
            if arguments[1] == "get":
                result["fields"][0]["value"] = "wrong-user"
            return result
        self.vault.after = after
        result, _, _ = self.run_verifier()
        self.assertEqual(result, 1)
        self.assertEqual(self.vault.writes, [("create", TEST_ID)])

    def test_read_failure_is_sanitized_and_not_retried(self):
        def before(arguments, payload):
            if arguments[1] == "get":
                raise RuntimeError(FIRST + PRIVATE_ERROR)
        self.vault.before = before
        result, _, _ = self.run_verifier()
        self.assertEqual(result, 1)
        self.assertEqual(sum(arguments[1] == "get" for arguments, _ in self.vault.calls), 1)
        self.assertEqual(self.vault.writes, [("create", TEST_ID)])

    def test_lookup_failure_cannot_be_mistaken_for_absence(self):
        self.cli.side_effect = RuntimeError(PRIVATE_ERROR + EXISTING)
        result, _, _ = self.run_verifier()
        self.assertEqual(result, 1)
        self.assertEqual(self.cli.call_count, 1)
        self.assertFalse(self.vault.writes)

    def test_existing_item_rename_during_approval_blocks_edit(self):
        self.existing()
        def answer(prompt):
            if "OVERWRITE " in prompt:
                self.vault.items[TEST_ID]["title"] = "NetPilot-Other-Test"
                return verifier.OVERWRITE_CONFIRMATION
            return verifier.CONFIRMATION
        result, _, _ = self.run_verifier(["--execute", "--overwrite-existing"], answer)
        self.assertEqual(result, 1)
        self.assertFalse(self.vault.writes)

    def test_wrong_category_duplicate_fields_and_unsupported_metadata_fail_closed(self):
        variants = [
            {"category": "SERVER"},
            {"files": [{"id": "fixture-attachment"}]},
            {"passkeys": [{"credentialId": "fixture-passkey"}]},
            {"fields": item(TEST_ID, verifier.TITLE)["fields"] + [{"label": "password", "value": EXISTING}]},
            {"fields": [{"id": "username", "type": "STRING"}, {"id": "password", "type": "STRING"}]},
            {"fields": [{"id": "username", "label": "password", "type": "CONCEALED", "value": EXISTING}]},
        ]
        for variant in variants:
            with self.subTest(variant=list(variant)):
                self.vault.items[TEST_ID] = item(TEST_ID, verifier.TITLE)
                self.vault.items[TEST_ID].update(variant)
                self.generated.side_effect = [FIRST, SECOND]
                result, _, _ = self.run_verifier(["--execute", "--overwrite-existing"],
                                                [verifier.CONFIRMATION, verifier.OVERWRITE_CONFIRMATION])
                self.assertEqual(result, 1)
                self.assertFalse(self.vault.writes)


if __name__ == "__main__":
    unittest.main()
