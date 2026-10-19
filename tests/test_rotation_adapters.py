"""Mocked Vault/SSH adapter tests; never read real tokens or contact services."""

from copy import deepcopy
import json
import traceback
import unittest
from unittest.mock import MagicMock, patch

from security import rotation_adapters as adapters


CURRENT_ID = "a" * 26
USERNAME = "fixture-rotation-user"
OLD = "fixture-old-password-only"
NEW = "fixture-new-password-only"
ROTATION = "fixture-rotation-id"


def item(reference=CURRENT_ID, title="NetPilot-Current", password=OLD, rotation=None, binding=None):
    fields = [
        {"id": "username", "label": "username", "type": "STRING", "value": USERNAME},
        {"id": "password", "label": "password", "type": "CONCEALED", "value": password},
    ]
    if rotation is not None:
        fields.append({"id": "netpilot_rotation_id", "label": "netpilot_rotation_id", "value": rotation})
    if binding is not None:
        fields.append({"id": "netpilot_current_reference", "label": "netpilot_current_reference", "value": binding})
    return {"id": reference, "title": title, "category": "LOGIN", "fields": fields,
            "notesPlain": "Preserve this existing metadata", "tags": ["existing-tag"]}


class FakeVault:
    def __init__(self):
        self.items = {CURRENT_ID: item()}
        self.calls, self.writes = [], []
        self.fail_after_edit = False
        self.ignore_edit = False

    def __call__(self, arguments, *, input_text=None):
        self.calls.append((list(arguments), input_text))
        operation = arguments[1]
        if operation == "list":
            return json.dumps([{"id": value["id"], "title": value["title"]} for value in self.items.values()])
        if operation == "get":
            reference = arguments[2]
            value = self.items.get(reference)
            if value is None:
                value = next(value for value in self.items.values() if value["title"] == reference)
            if "--fields" in arguments:
                return json.dumps([field for field in value["fields"] if field.get("label") in ("username", "password")])
            return json.dumps(value)
        if operation == "template":
            template = item()
            template.pop("id")
            return json.dumps(template)
        if operation == "create":
            value = json.loads(input_text)
            value["id"] = chr(ord("a") + len(self.items)) * 26
            self.items[value["id"]] = value
            self.writes.append(("create", value["id"]))
            return json.dumps(value)
        if operation == "edit":
            value = json.loads(input_text)
            self.writes.append(("edit", value["id"]))
            if not self.ignore_edit:
                self.items[value["id"]] = value
            if self.fail_after_edit:
                self.fail_after_edit = False
                raise RuntimeError(NEW + " private-vault-response")
            return json.dumps(value)
        raise AssertionError("Unexpected mock CLI operation")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.vault = FakeVault()
        self.store = adapters.OnePasswordStore()
        cli = patch.object(adapters.credential_provider, "_run_op", side_effect=self.vault)
        self.cli = cli.start()
        self.addCleanup(cli.stop)
        token = patch.object(adapters.credential_provider, "_read_token", side_effect=AssertionError("Real token access prohibited"))
        self.token = token.start()
        self.addCleanup(token.stop)

    def prepared(self):
        current = self.store.read_current()
        previous = self.store.archive_current(ROTATION, current)
        pending = self.store.stage_pending(ROTATION, USERNAME, NEW, current_reference=current.reference)
        return current, previous, pending

    def assert_error(self, category, call):
        with self.assertRaises(adapters.AdapterError) as caught:
            call()
        self.assertEqual(caught.exception.category, category)
        formatted = "".join(traceback.format_exception(caught.exception))
        for secret in (USERNAME, OLD, NEW, "private-vault-response"):
            self.assertNotIn(secret, formatted)

    def test_credential_repr_hides_all_fields(self):
        credential = self.store.read_current()
        self.assertEqual(repr(credential), "<Credential redacted>")
        self.assertNotIn(OLD, str(credential))
        self.assertNotIn(USERNAME, str(credential))

    def test_current_read_and_pending_absence_are_read_only(self):
        current = self.store.read_current()
        self.assertEqual((current.reference, current.username, current.password), (CURRENT_ID, USERNAME, OLD))
        self.assertIsNone(self.store.find_pending())
        self.assertEqual(self.vault.writes, [])
        self.token.assert_not_called()

    def test_current_category_is_preserved_without_assuming_login(self):
        self.vault.items[CURRENT_ID]["category"] = "SERVER"
        current, _, pending = self.prepared()
        self.store.promote(current, pending)
        self.assertEqual(self.vault.items[CURRENT_ID]["category"], "SERVER")

    def test_current_consumer_provider_must_observe_the_same_pair(self):
        with patch.object(adapters.credential_provider, "get_credentials", return_value=(USERNAME, NEW)):
            self.assert_error("vault_conflict", self.store.read_current)

    def test_pending_lookup_failure_is_never_treated_as_absence(self):
        self.cli.side_effect = RuntimeError("private-vault-response " + OLD)
        self.assert_error("vault_read", self.store.find_pending)

    def test_duplicate_current_or_pending_titles_are_rejected(self):
        for title in ("NetPilot-Current", "NetPilot-Pending"):
            with self.subTest(title=title):
                self.vault.items = {"a" * 26: item("a" * 26, title), "b" * 26: item("b" * 26, title)}
                self.assert_error("vault_conflict", self.store.read_current if title == "NetPilot-Current" else self.store.find_pending)

    def test_stage_is_idempotent_and_preserves_current(self):
        current, _, pending = self.prepared()
        before = len(self.vault.writes)
        same = self.store.stage_pending(ROTATION, USERNAME, NEW, current_reference=CURRENT_ID)
        self.assertEqual(same, pending)
        self.assertEqual(len(self.vault.writes), before)
        self.assertEqual(self.store.read_current(), current)

    def test_existing_unowned_pending_is_not_overwritten(self):
        self.vault.items["b" * 26] = item("b" * 26, "NetPilot-Pending", NEW)
        self.assert_error("vault_conflict", lambda: self.store.stage_pending(ROTATION, USERNAME, NEW, CURRENT_ID))
        self.assertEqual(self.vault.writes, [])

    def test_other_rotation_or_binding_is_rejected(self):
        _, _, pending = self.prepared()
        self.assert_error("vault_conflict", lambda: self.store.stage_pending("different-rotation", USERNAME, NEW, CURRENT_ID))
        self.assert_error("vault_conflict", lambda: self.store.stage_pending(ROTATION, USERNAME, NEW, "z" * 26))
        self.assertEqual(self.store.find_pending(), pending)

    def test_same_password_or_different_username_is_rejected(self):
        self.assert_error("vault_conflict", lambda: self.store.stage_pending(ROTATION, USERNAME, OLD, CURRENT_ID))
        self.assert_error("vault_conflict", lambda: self.store.stage_pending(ROTATION, "different-user", NEW, CURRENT_ID))
        self.assertEqual(self.vault.writes, [])

    def test_previous_archive_is_idempotent_and_never_overwritten(self):
        current, previous, _ = self.prepared()
        count = len(self.vault.writes)
        self.assertEqual(self.store.archive_current(ROTATION, current), previous)
        self.assertEqual(len(self.vault.writes), count)
        changed = adapters.Credential(CURRENT_ID, USERNAME, NEW)
        self.assert_error("vault_conflict", lambda: self.store.archive_current(ROTATION, changed))

    def test_archive_refuses_changed_current(self):
        current = self.store.read_current()
        self.vault.items[CURRENT_ID] = item(password="different-current-value")
        self.assert_error("vault_conflict", lambda: self.store.archive_current(ROTATION, current))
        self.assertEqual(self.vault.writes, [])

    def test_promote_requires_verified_previous_archive(self):
        current = self.store.read_current()
        pending = self.store.stage_pending(ROTATION, USERNAME, NEW, CURRENT_ID)
        self.assert_error("vault_conflict", lambda: self.store.promote(current, pending))
        self.assertFalse(any(operation == "edit" for operation, _ in self.vault.writes))

    def test_promotion_preserves_current_metadata_pending_and_previous(self):
        current, previous, pending = self.prepared()
        updated = self.store.promote(current, pending)
        self.assertEqual(updated.reference, CURRENT_ID)
        self.assertEqual(updated.password, NEW)
        self.assertEqual(self.store.read(previous.reference).password, OLD)
        self.assertEqual(self.store.read(pending.reference).password, NEW)
        self.assertEqual(self.vault.items[CURRENT_ID]["notesPlain"], "Preserve this existing metadata")
        self.assertEqual(self.vault.items[CURRENT_ID]["tags"], ["existing-tag"])
        for arguments, payload in self.vault.calls:
            for secret in (USERNAME, OLD, NEW):
                self.assertNotIn(secret, repr(arguments))
            if arguments[1] in ("create", "edit"):
                self.assertIsInstance(payload, str)
                self.assertNotIn("--template", arguments)

    def test_observed_current_drift_blocks_promotion(self):
        current, _, pending = self.prepared()
        self.vault.items[CURRENT_ID] = item(password="out-of-band-current-change")
        self.assert_error("vault_conflict", lambda: self.store.promote(current, pending))
        self.assertFalse(any(operation == "edit" for operation, _ in self.vault.writes))

    def test_pending_replacement_with_new_id_is_conflicting(self):
        current, _, pending = self.prepared()
        value = self.vault.items.pop(pending.reference)
        value["id"] = "z" * 26
        self.vault.items[value["id"]] = value
        self.assert_error("vault_conflict", lambda: self.store.promote(current, pending))

    def test_readback_mismatch_cannot_report_commit(self):
        current, _, pending = self.prepared()
        self.vault.ignore_edit = True
        self.assert_error("vault_conflict", lambda: self.store.promote(current, pending))
        self.assertEqual(self.store.read_current().password, OLD)

    def test_uncertain_commit_can_reconcile_without_deleting_recovery(self):
        current, previous, pending = self.prepared()
        self.vault.fail_after_edit = True
        self.assert_error("vault_write", lambda: self.store.promote(current, pending))
        self.assertEqual(self.store.read(previous.reference).password, OLD)
        self.assertEqual(self.store.find_pending(), pending)
        count = len(self.vault.writes)
        self.assertEqual(self.store.promote(current, pending).password, NEW)
        self.assertEqual(len(self.vault.writes), count)

    def test_restore_current_keeps_both_recovery_items(self):
        current, previous, pending = self.prepared()
        promoted = self.store.promote(current, pending)
        restored = self.store.restore_current(promoted, previous)
        self.assertEqual(restored.password, OLD)
        self.assertEqual(self.store.read(previous.reference), previous)
        self.assertEqual(self.store.read(pending.reference), pending)
        self.assertEqual(self.store.restore_current(promoted, previous).password, OLD)

    def test_restore_refuses_unrelated_previous(self):
        current, previous, pending = self.prepared()
        promoted = self.store.promote(current, pending)
        unrelated = adapters.Credential(previous.reference, USERNAME, OLD, ROTATION, "z" * 26)
        self.assert_error("vault_conflict", lambda: self.store.restore_current(promoted, unrelated))

    def test_invalid_references_fail_before_cli(self):
        for reference in (None, "--vault", "item\npassword", "", "not-an-item-id"):
            with self.subTest(reference=reference):
                self.assert_error("credentials", lambda: self.store.read(reference))
        self.cli.assert_not_called()

    def test_ambiguous_fields_fail_closed(self):
        self.vault.items[CURRENT_ID]["fields"].append({"label": "password", "value": NEW})
        self.assert_error("vault_conflict", self.store.read_current)

    def test_unpreservable_passkeys_or_files_block_current_edit(self):
        current, _, pending = self.prepared()
        self.vault.items[CURRENT_ID]["passkeys"] = [{"credentialId": "fixture-only"}]
        self.assert_error("blocked", lambda: self.store.promote(current, pending))
        self.assertFalse(any(operation == "edit" for operation, _ in self.vault.writes))

    def test_corrupted_previous_transaction_metadata_blocks_promotion_before_edit(self):
        current, previous, pending = self.prepared()
        original = deepcopy(self.vault.items[previous.reference])
        before = list(self.vault.writes)
        for key, value in (("netpilot_rotation_id", "foreign-rotation"),
                           ("netpilot_current_reference", "z" * 26),
                           ("password", "foreign-original-password")):
            with self.subTest(field=key):
                self.vault.items[previous.reference] = deepcopy(original)
                fields = self.vault.items[previous.reference]["fields"]
                next(field for field in fields if field["id"] == key)["value"] = value
                self.assert_error("vault_conflict", lambda: self.store.promote(current, pending))
                self.assertEqual(self.vault.writes, before)
                self.assertEqual(self.store.read_current(), current)
                self.assertEqual(self.store.find_pending(), pending)

    def test_malformed_vault_templates_cannot_create_pending_credentials(self):
        for template in (None, [], {"fields": "private-vault-response"},
                         {"fields": ["private-vault-response"]}):
            with self.subTest(template_type=type(template).__name__):
                def reply(arguments, **kwargs):
                    if arguments[1] == "template":
                        return json.dumps(template)
                    return self.vault(arguments, **kwargs)

                self.cli.side_effect = reply
                self.assert_error("credentials", lambda: self.store.stage_pending(
                    ROTATION, USERNAME, NEW, CURRENT_ID))
                self.assertEqual(self.vault.writes, [])
                self.assertEqual(set(self.vault.items), {CURRENT_ID})

    def test_malformed_item_metadata_is_rejected_without_writing_or_leaking(self):
        original = item()
        changes = ({"id": "z" * 26}, {"category": None}, {"fields": None},
                   {"fields": ["private-vault-response"]},
                   {"title": "private-vault-response"})
        for change in changes:
            with self.subTest(field=next(iter(change))):
                response = dict(original, **change)
                self.cli.side_effect = lambda arguments, **kwargs: json.dumps(response)
                self.assert_error("credentials", lambda: self.store.read(CURRENT_ID))
                self.assertEqual(self.vault.writes, [])
                self.assertTrue(all(call.args[0][:2] == ["item", "get"]
                                    for call in self.cli.call_args_list))

    def test_invalid_cli_json_is_sanitized(self):
        self.cli.side_effect = None
        self.cli.return_value = OLD + " private-vault-response"
        self.assert_error("vault_read", self.store.read_current)


class DeviceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.adapter = adapters.NetmikoDeviceAdapter()
        self.credential = adapters.Credential(CURRENT_ID, "admin", OLD)
        factory = patch.object(adapters, "ConnectHandler")
        self.connect = factory.start()
        self.addCleanup(factory.stop)
        self.session = self.connect.return_value
        self.session.send_command.side_effect = self.answer

    @staticmethod
    def answer(command, **kwargs):
        return {
            "show version | json": json.dumps({"modelName": "cEOSLab", "version": "4.36.2F"}),
            "show hostname | json": json.dumps({"hostname": "R1"}),
            "show privilege": "Current privilege level is 15\n",
            "show running-config": "hostname R1\nusername admin privilege 15 role network-admin secret sha512 $6$fixture$" + "A" * 86 + "\nend\n",
        }[command]

    def assert_category(self, category):
        with self.assertRaises(adapters.AdapterError) as caught:
            self.adapter.authenticate("R1", "192.0.2.1", self.credential)
        self.assertEqual(caught.exception.category, category)
        for secret in (USERNAME, OLD, NEW):
            self.assertNotIn(secret, "".join(traceback.format_exception(caught.exception)))

    def test_fresh_password_only_session_with_identity_and_privilege_checks(self):
        self.adapter.authenticate("R1", "192.0.2.1", self.credential)
        self.adapter.authenticate("R1", "192.0.2.1", self.credential)
        self.assertEqual(self.connect.call_count, 2)
        self.assertEqual(self.session.disconnect.call_count, 2)
        options = self.connect.call_args.kwargs
        self.assertFalse(options["ssh_strict"])
        self.assertFalse(options["system_host_keys"])
        self.assertFalse(options["use_keys"])
        self.assertFalse(options["allow_agent"])
        self.assertIsNone(options["session_log"])
        self.assertEqual(options["password"], OLD)
        self.session.enable.assert_not_called()
        self.session.send_config_set.assert_not_called()
        self.session.save_config.assert_not_called()

    def test_explicit_rejection_is_authentication_only(self):
        self.connect.side_effect = adapters.NetmikoAuthenticationException(OLD)
        self.assert_category("authentication")

    def test_timeouts_are_unknown_access_not_authentication_rejections(self):
        self.connect.side_effect = adapters.NetmikoTimeoutException(OLD)
        self.assert_category("unreachable")

    def test_unexpected_network_exception_is_sanitized(self):
        self.connect.side_effect = RuntimeError(OLD)
        self.assert_category("unreachable")

    def test_wrong_hostname_or_platform_is_rejected_and_disconnected(self):
        for replacement in ({"hostname": "R2"}, {"modelName": "other-platform", "version": "x"}):
            self.session.send_command.side_effect = lambda command, **kwargs: self.answer(command) if command == "show privilege" else json.dumps(replacement)
            self.assert_category("identity")
        self.assertEqual(self.session.disconnect.call_count, 2)

    def test_insufficient_privilege_is_not_authenticated_success(self):
        self.session.send_command.side_effect = lambda command, **kwargs: "Current privilege level is 1" if command == "show privilege" else self.answer(command)
        self.assert_category("privilege")
        self.session.disconnect.assert_called_once_with()

    def test_malformed_identity_response_is_sanitized(self):
        self.session.send_command.side_effect = lambda command, **kwargs: self.answer(command) if command == "show privilege" else OLD
        self.assert_category("identity")

    def test_live_support_does_not_invent_recovery_login_or_allow_other_accounts(self):
        self.assertTrue(self.adapter.live_writes_supported)
        self.assertEqual(self.adapter.blockers(), [])
        self.assertFalse(self.adapter.verify_recovery("R1", "192.0.2.1", "admin"))
        other = adapters.Credential(CURRENT_ID, "netpilot-recovery", OLD)
        with self.assertRaises(adapters.AdapterError) as caught:
            self.adapter.change_password("R1", "192.0.2.1", self.credential, other)
        self.assertEqual(caught.exception.category, "credentials")
        self.connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
