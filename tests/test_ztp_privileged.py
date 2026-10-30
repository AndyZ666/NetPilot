"""Offline tests for the root helper's real validation and reconciliation gate."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lab8 import ztp_privileged as helper


def request(name="R8"):
    interface, mac = helper.identities(name)
    return {"hostname": name, "management_ip": "172.20.20.32",
            "bootstrap_mac": mac, "host_interface": interface, "job_id": "a" * 32}


def plan():
    return {"dry-run": True, "deployed-lab": False, "added-nodes": ["R8"],
            "deleted-nodes": [], "recreated-nodes": [], "started-nodes": [],
            "added-links": ["R8:eth1 -- host:" + request()["host_interface"]],
            "deleted-endpoints": [], "restarted-nodes": []}


def baseline():
    return {"name": "pilot-network", "mgmt": {"network": "clab", "ipv4-subnet": "172.20.20.0/24"},
            "topology": {"kinds": {"ceos": {"image": "ceos:4.36.2F"}},
                         "nodes": {"R6": {"kind": "ceos", "mgmt-ipv4": "172.20.20.30"},
                                   "H1": {"kind": "linux"}},
                         "links": [{"endpoints": ["R6:eth2", "H1:eth1"]}]}}


def created_node():
    return {"Id": "c" * 64, "Name": "/clab-pilot-network-R8", "Config": {
        "Image": "ceos:4.36.2F", "Labels": {"containerlab": "pilot-network", "clab-node-name": "R8",
        "netpilot-ztp-job-id": "a" * 32}},
        "NetworkSettings": {"Networks": {"clab": {"IPAddress": "172.20.20.32"}}}}


class RestrictedProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.forbidden = self.enterContext(patch.object(
            helper.subprocess, "run", side_effect=AssertionError("Real process execution forbidden")))

    def tearDown(self):
        self.forbidden.assert_not_called()

    def test_valid_request_and_case_insensitive_stable_bootstrap_identity(self):
        value = request()
        self.assertEqual(helper.validate_request(value), value)
        self.assertEqual(helper.identities("r8"), helper.identities("R8"))
        self.assertEqual(len(value["host_interface"]), 14)
        self.assertTrue(value["bootstrap_mac"].startswith("02:08:"))

    def test_rejects_shell_names_extra_paths_bad_ips_and_forged_bootstrap_identity(self):
        invalid = [dict(request(), hostname=name) for name in
                   ("R8;id", "../R8", "-R8", "R8.", "R8\n", "a" * 33)]
        invalid += [dict(request(), management_ip=address) for address in
                    (True, 123, "172.20.20.1", "172.20.20.0", "172.20.20.255", "172.31.252.8", "malformed")]
        invalid += [dict(request(), path="/tmp/attacker.yml"),
                    dict(request(), host_interface="eth0"), dict(request(), bootstrap_mac="02:00:00:00:00:01"),
                    dict(request(), job_id="../another-job")]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(helper.ProvisionError):
                helper.validate_request(value)

    def test_real_apply_result_permits_only_new_node_and_its_host_link(self):
        self.assertEqual(helper.check_plan(plan(), request()), plan())
        no_op = dict(plan(), **{"added-nodes": [], "added-links": []})
        self.assertEqual(helper.check_plan(no_op, request(), retry=True), no_op)
        with self.assertRaises(helper.ProvisionError):
            helper.check_plan(no_op, request())

    def test_existing_node_recreation_restart_start_or_endpoint_deletion_blocks(self):
        for action in ("deleted-nodes", "recreated-nodes", "started-nodes", "restarted-nodes", "deleted-endpoints"):
            value = dict(plan(), **{action: ["H1"]})
            with self.subTest(action=action), self.assertRaisesRegex(helper.ProvisionError, "existing"):
                helper.check_plan(value, request())

    def test_unknown_initial_lab_and_other_link_plans_fail_closed(self):
        invalid = [dict(plan(), **{"deployed-lab": True}), dict(plan(), **{"dry-run": False}),
                   dict(plan(), **{"new-unknown-action": ["R1"]}),
                   dict(plan(), **{"added-nodes": ["R8", "R9"]}),
                   dict(plan(), **{"added-links": ["R8:eth1 -- R6:eth4"]}),
                   dict(plan(), **{"node-change-reasons": {"H1": "config drift: exec"}}),
                   dict(plan(), **{"recreated-nodes": None}), {"dry-run": True}]
        for value in invalid:
            with self.subTest(plan=value), self.assertRaises(helper.ProvisionError):
                helper.check_plan(value, request())

    def test_candidate_preserves_existing_safe_definitions_and_links(self):
        original = baseline()
        saved = copy.deepcopy(original)
        value = helper.candidate(original, request())
        self.assertEqual(original, saved)
        for name, node in saved["topology"]["nodes"].items():
            self.assertEqual(value["topology"]["nodes"][name], node)
        self.assertEqual(value["topology"]["links"][:-1], saved["topology"]["links"])
        new = value["topology"]["nodes"]["R8"]
        self.assertEqual(new["mgmt-ipv4"], "172.20.20.32")
        self.assertIs(new["suppress-startup-config"], True)
        self.assertNotIn("startup-config", new)
        self.assertNotIn("exec", new)
        self.assertEqual(value["topology"]["links"][-1], {
            "type": "host", "endpoint": {"node": "R8", "interface": "eth1", "mac": request()["bootstrap_mac"]},
            "host-interface": request()["host_interface"]})

    def test_candidate_rejects_case_insensitive_duplicate_and_ip_collision(self):
        for value in (request("r6"), dict(request(), management_ip="172.20.20.30")):
            with self.subTest(request=value), self.assertRaises(helper.ProvisionError):
                helper.candidate(baseline(), value)

    def test_unsafe_dry_run_prevents_actual_deployment_and_journal_write(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = {"names": ["R6"], "addresses": ["172.20.20.30"], "macs": []}
            unsafe = dict(plan(), **{"recreated-nodes": ["H1", "web-server"]})
            with patch.object(helper, "STATE", Path(directory)), \
                    patch.object(helper, "_records", return_value={}), \
                    patch.object(helper, "_read_root_json", return_value=baseline()), \
                    patch.object(helper, "_runtime_claim", return_value=None), \
                    patch.object(helper, "_existing_fingerprint", return_value=[]), \
                    patch.object(helper, "_secure_directory"), \
                    patch.object(helper, "_write_root_json") as write, \
                    patch.object(helper, "_run", return_value=json.dumps(unsafe)) as run:
                with self.assertRaises(helper.ProvisionError):
                    helper.reconcile(request(), apply=True)
                self.assertEqual(run.call_count, 1)
                self.assertIn("--dry-run", run.call_args.args[0])
                self.assertIn("--skip-post-deploy", run.call_args.args[0])
                self.assertNotIn("--node-filter", run.call_args.args[0])
                self.assertFalse(any(call.args[0].name == "jobs.json" for call in write.call_args_list))

    def test_different_recorded_running_state_blocks_before_containerlab(self):
        recorded = baseline()
        recorded["topology"]["nodes"]["H1"]["exec"] = ["old host command"]
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(helper, "STATE", Path(directory)), \
                patch.object(helper, "_records", return_value={}), \
                patch.object(helper, "_read_root_json", side_effect=[baseline(), recorded]), \
                patch.object(helper, "_runtime_claim", return_value=None), \
                patch.object(helper, "_existing_fingerprint", return_value=[]), \
                patch.object(helper, "_secure_directory"), patch.object(helper, "_write_root_json") as write, \
                patch.object(helper, "_run") as run:
            with self.assertRaisesRegex(helper.ProvisionError, "running-lab state"):
                helper.reconcile(request(), apply=True)
            run.assert_not_called()
            write.assert_not_called()

    def test_owned_retry_rejects_replaced_container_or_different_job(self):
        entry = {"request": request(), "node_id": "old-id"}
        record = {"r8": entry}
        with patch.object(helper, "_docker_state", return_value=({}, [
                {"Name": "/clab-pilot-network-R8", "Id": "new-id"}])):
            with self.assertRaisesRegex(helper.ProvisionError, "identity changed"):
                helper._owned(request(), record, require_node=True)
        with self.assertRaisesRegex(helper.ProvisionError, "not owned"):
            helper._owned(dict(request(), job_id="b" * 32), record)

    def test_reserved_preview_does_not_bypass_new_docker_ip_collision(self):
        records = {"r8": {"request": request(), "node_id": None}}
        occupied = {"Id": "d" * 64, "Name": "/unrelated", "Config": {"Hostname": "unrelated"},
                    "NetworkSettings": {"Networks": {"clab": {"IPAddress": "172.20.20.32"}}}}
        with patch.object(helper, "_docker_state", return_value=({}, [occupied])):
            with self.assertRaisesRegex(helper.ProvisionError, "already allocated"):
                helper._runtime_claim(request(), records)
        records["r9"] = {"request": request("R9"), "node_id": None}
        with patch.object(helper, "_docker_state", return_value=({}, [])):
            with self.assertRaisesRegex(helper.ProvisionError, "reserved"):
                helper._runtime_claim(request(), records)

    def test_interrupted_own_deployment_requires_exact_job_image_and_address(self):
        records = {"r8": {"request": request(), "node_id": None}}
        node = created_node()
        with patch.object(helper, "_docker_state", return_value=({}, [node])), \
                patch.object(helper, "_host_endpoint", return_value=None):
            self.assertEqual(helper._runtime_claim(request(), records), node)
        for mutation in ("job", "image", "address"):
            forged = copy.deepcopy(node)
            if mutation == "job":
                forged["Config"]["Labels"]["netpilot-ztp-job-id"] = "b" * 32
            elif mutation == "image":
                forged["Config"]["Image"] = "unapproved-image"
            else:
                forged["NetworkSettings"]["Networks"]["clab"]["IPAddress"] = "172.20.20.33"
            with self.subTest(mutation=mutation), \
                    patch.object(helper, "_docker_state", return_value=({}, [forged])):
                with self.assertRaises(helper.ProvisionError):
                    helper._runtime_claim(request(), records)

    def test_safe_new_node_apply_runs_checked_dry_run_first_and_records_identity(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(helper, "STATE", Path(directory)), \
                patch.object(helper, "_records", return_value={}), \
                patch.object(helper, "_read_root_json", return_value=baseline()), \
                patch.object(helper, "_runtime_claim", return_value=None), \
                patch.object(helper, "_existing_fingerprint", return_value=[("existing-id", "R6", "unchanged", "running")]), \
                patch.object(helper, "_secure_directory"), \
                patch.object(helper, "_write_root_json") as write, \
                patch.object(helper, "_docker_state", return_value=({}, [created_node()])), \
                patch.object(helper, "_run", side_effect=[json.dumps(plan()), "[]"]) as run:
            result = helper.reconcile(request(), apply=True)
            self.assertEqual(result, {"node_id": "c" * 64, "retry": False})
            first, second = [call.args[0] for call in run.call_args_list]
            self.assertEqual(first, second + ["--dry-run"])
            self.assertIn(str(Path(directory) / "candidate.clab.yml"), second)
            for forbidden in ("--reconfigure", "--node-filter", "destroy"):
                self.assertNotIn(forbidden, second)
            journals = [call.args[1] for call in write.call_args_list if call.args[0].name == "jobs.json"]
            self.assertEqual(journals[-1]["r8"]["node_id"], "c" * 64)
            approved = [call.args[1] for call in write.call_args_list if call.args[0].name == "approved.json"]
            self.assertEqual(approved[0]["topology"]["nodes"]["R8"]["labels"], {"netpilot-ztp-job-id": "a" * 32})

    def test_runtime_changes_between_plan_and_apply_prevent_deployment(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(helper, "STATE", Path(directory)), \
                patch.object(helper, "_records", return_value={}), \
                patch.object(helper, "_read_root_json", return_value=baseline()), \
                patch.object(helper, "_runtime_claim", return_value=None), \
                patch.object(helper, "_existing_fingerprint", side_effect=[["old"], ["changed"]]), \
                patch.object(helper, "_secure_directory"), patch.object(helper, "_write_root_json"), \
                patch.object(helper, "_docker_state", return_value=({}, [])), \
                patch.object(helper, "_run", return_value=json.dumps(plan())) as run:
            with self.assertRaisesRegex(helper.ProvisionError, "state changed"):
                helper.reconcile(request(), apply=True)
            self.assertEqual(run.call_count, 1)
            self.assertIn("--dry-run", run.call_args.args[0])

    def test_attach_never_moves_an_endpoint_from_another_bridge(self):
        with patch.object(helper, "_owned", return_value=({}, created_node())), \
                patch.object(helper, "_records", return_value={}), \
                patch.object(helper, "_json", return_value=[{"linkinfo": {"info_kind": "bridge"}}]), \
                patch.object(helper, "_host_endpoint", return_value={
                    "linkinfo": {"info_kind": "veth"}, "master": "unrelated-bridge"}), \
                patch.object(helper, "_run") as run:
            with self.assertRaises(helper.ProvisionError):
                helper.attach(request())
            run.assert_not_called()

    def test_existing_unowned_bootstrap_endpoint_prevents_first_deployment(self):
        with patch.object(helper, "_docker_state", return_value=({}, [])), \
                patch.object(helper, "_host_endpoint", return_value={"ifindex": 12}):
            with self.assertRaisesRegex(helper.ProvisionError, "already exists"):
                helper._runtime_claim(request(), {})

    def test_bootstrap_peer_requires_matching_veth_indices_and_pinned_mac(self):
        node = dict(created_node(), State={"Pid": 1234})
        endpoint = {"ifindex": 42, "link_index": 7, "linkinfo": {"info_kind": "veth"}}
        peer = {"ifindex": 7, "link_index": 42, "address": request()["bootstrap_mac"]}
        with patch.object(helper, "_json", return_value=[peer]) as read:
            helper._verify_endpoint(endpoint, node, request())
            read.assert_called_once_with(["/usr/bin/nsenter", "--target", "1234", "--net", "/usr/sbin/ip",
                                          "-j", "-d", "link", "show", "dev", "eth1"])
        for wrong in (dict(peer, link_index=99), dict(peer, address="02:00:00:00:00:01")):
            with self.subTest(peer=wrong), patch.object(helper, "_json", return_value=[wrong]):
                with self.assertRaises(helper.ProvisionError):
                    helper._verify_endpoint(endpoint, node, request())

    def test_dhcp_reload_targets_only_fixed_server_and_requires_prepared_server(self):
        records = {"r8": {"request": request()}}
        with patch.object(helper, "_records", return_value=records), \
                patch.object(helper, "snapshot", return_value={"server_ready": False}), \
                patch.object(helper, "_run") as run:
            with self.assertRaises(helper.ProvisionError):
                helper.reload_dhcp(request())
            run.assert_not_called()
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(helper, "STATE", Path(directory)), \
                patch.object(helper, "_records", return_value=records), \
                patch.object(helper, "snapshot", return_value={"server_ready": True}), \
                patch.object(helper.Path, "lstat") as lstat, \
                patch.object(helper, "_write_root_text") as write, \
                patch.object(helper, "_run") as run:
            lstat.return_value.st_mode = 0o040755
            lstat.return_value.st_uid = 0
            helper.reload_dhcp(request())
            run.assert_called_once_with(["/usr/bin/docker", "kill", "--signal", "HUP",
                                        "clab-netpilot-ztp-infra-ztp-server"])
            self.assertEqual(write.call_count, 2)
            self.assertIn(request()["bootstrap_mac"], write.call_args_list[0].args[1])
            self.assertIn("67,http://10.250.0.1/day0/R8.cfg", write.call_args_list[1].args[1])

    def test_snapshot_collects_docker_allocations_without_leaking_container_environment(self):
        network = {"IPAM": {"Config": [{"Subnet": "172.20.20.0/24", "Gateway": "172.20.20.1",
                                       "AuxiliaryAddresses": {"reserved": "172.20.20.100"}}]},
                   "Containers": {"id": {"IPv4Address": "172.20.20.44/24"}}}
        containers = [{"Name": "/clab-pilot-network-r8", "Config": {
            "Hostname": "r8", "Labels": {"clab-node-name": "r8"}, "Env": ["TOKEN=secret"]},
            "NetworkSettings": {"Networks": {"clab": {"IPAddress": "172.20.20.32", "MacAddress": "02:AA:00:00:00:01"}}}}]
        with patch.object(helper, "_docker_state", return_value=(network, containers)), \
                patch.object(helper, "_records", return_value={}):
            value = helper.snapshot()
        self.assertIn("r8", value["names"])
        self.assertTrue({"172.20.20.1", "172.20.20.32", "172.20.20.44", "172.20.20.100"} <= set(value["addresses"]))
        self.assertEqual(value["macs"], ["02:aa:00:00:00:01"])
        self.assertFalse(value["server_ready"])
        self.assertNotIn("secret", json.dumps(value))


if __name__ == "__main__":
    unittest.main()
