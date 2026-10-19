"""Offline journal tests: only synthetic metadata and temporary private paths."""

from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

from security import rotation_state as state


STAMP = '2026-10-12T12:00:00+00:00'


def example(phase='PRECHECK'):
    return {
        'version': 1, 'rotation_id': '1' * 32,
        'started_at': STAMP, 'updated_at': STAMP, 'ended_at': None,
        'phase': phase, 'scope': ['R1'], 'username': 'lab_operator',
        'devices': {
            name: {'management_ip': f'192.0.2.{index}', 'state': 'pending',
                   'attempted': False, 'verified_at': None, 'last_error': None}
            for index, name in enumerate(state.FLEET, 1)
        },
        'credential_refs': {'current': 'current_item_id', 'pending': None, 'previous': None},
        'vault_state': 'unchanged', 'monitoring_state': 'not_requested', 'events': [],
    }


class SchemaTests(unittest.TestCase):
    def test_success_and_explicit_recovery_paths_have_independent_transition_expectations(self):
        # Specify the workflow contract independently of PHASES/TRANSITIONS:
        # prepare, change, verify, commit; failures may reconcile or roll back.
        paths = (
            ("IDLE", "PRECHECK", "PREPARED", "ROTATING", "VERIFYING",
             "READY_TO_COMMIT", "COMMITTING", "COMMITTED"),
            ("ROTATING", "PARTIAL_FAILURE", "ROLLING_BACK", "ROLLED_BACK"),
            ("VERIFYING", "RECOVERY_REQUIRED", "VERIFYING", "READY_TO_COMMIT"),
            ("PRECHECK", "ERROR", "PRECHECK"),
        )
        for path in paths:
            for current, following in zip(path, path[1:]):
                with self.subTest(current=current, following=following):
                    self.assertEqual(state.transition(current, following), following)

    def test_premature_promotion_and_terminal_reentry_are_forbidden_independently(self):
        forbidden = (
            ("IDLE", "ROTATING"), ("PRECHECK", "COMMITTING"),
            ("PREPARED", "READY_TO_COMMIT"), ("ROTATING", "COMMITTING"),
            ("VERIFYING", "COMMITTED"), ("READY_TO_COMMIT", "COMMITTED"),
            ("PARTIAL_FAILURE", "COMMITTED"), ("RECOVERY_REQUIRED", "COMMITTED"),
            ("ROLLING_BACK", "COMMITTED"), ("COMMITTED", "ROTATING"),
            ("COMMITTED", "COMMITTING"), ("ROLLED_BACK", "ROTATING"),
            ("ERROR", "PREPARED"),
        )
        for current, following in forbidden:
            with self.subTest(current=current, following=following):
                with self.assertRaises(state.StateError):
                    state.transition(current, following)

    def test_valid_single_fleet_events_and_nullable_fields(self):
        record = example()
        before = deepcopy(record)
        self.assertEqual(state.validate_state(record), before)
        self.assertEqual(record, before)
        record['scope'] = list(state.FLEET)
        record['credential_refs'].update(pending='pending.item-id', previous='previous_item_id')
        record['devices']['R1'].update(state='verified_new', attempted=True, verified_at=STAMP)
        record['events'] = [{'at': STAMP, 'phase': 'PRECHECK', 'operation': operation, 'device': None,
                             'result': 'INFO', 'error': None} for operation in state.OPERATIONS]
        state.validate_state(record)
        for category in state.ERROR_CATEGORIES:
            record['events'][0]['error'] = category
            record['devices']['R1']['last_error'] = category
            state.validate_state(record)

    def test_read_only_monitoring_verification_can_remain_required(self):
        record = example('RECOVERY_REQUIRED')
        record['monitoring_state'] = 'verification_required'
        record['devices']['R1'].update(state='verified_old', attempted=True, verified_at=STAMP)
        self.assertEqual(state.validate_state(record)['monitoring_state'], 'verification_required')

    def test_all_explicit_transitions_and_no_implicit_jumps(self):
        for current in state.PHASES:
            for new in state.PHASES:
                with self.subTest(current=current, new=new):
                    if new in state.TRANSITIONS[current]:
                        self.assertEqual(state.transition(current, new), new)
                    else:
                        with self.assertRaises(state.StateError):
                            state.transition(current, new)
        for old, new in [('unknown', 'PRECHECK'), (None, 'ERROR'), ('IDLE', []), ({}, 'ERROR')]:
            with self.assertRaises(state.StateError):
                state.transition(old, new)

    def test_invalid_shapes_scopes_enums_dates_and_values_fail_closed(self):
        mutations = [
            lambda r: r.update(version=True),
            lambda r: r.update(rotation_id='../invalid'),
            lambda r: r.update(started_at='2026-02-31T12:00:00Z'),
            lambda r: r.update(updated_at='2026-10-12T12:00:00'),
            lambda r: r.update(ended_at='2026-10-12T12:00:00-06:00'),
            lambda r: r.update(phase='NEARLY_DONE'),
            lambda r: r.update(scope=['R2']),
            lambda r: r.update(scope=list(reversed(state.FLEET))),
            lambda r: r.update(scope=['R1', 'R1']),
            lambda r: r.update(username='operator\ncommand'),
            lambda r: r.update(username='x' * 65),
            lambda r: r['devices'].pop('S4'),
            lambda r: r['devices'].update(TEST_R10={}),
            lambda r: r['devices']['R1'].update(attempted=1),
            lambda r: r['devices']['R1'].update(state='command_sent'),
            lambda r: r['devices']['R1'].update(management_ip='192.0.2.1/24'),
            lambda r: r['devices']['R1'].update(management_ip='2001:db8::1'),
            lambda r: r['devices']['R2'].update(management_ip='192.0.2.1'),
            lambda r: r['devices']['R1'].update(verified_at='yesterday'),
            lambda r: r['credential_refs'].update(current=None),
            lambda r: r['credential_refs'].update(pending='../outside'),
            lambda r: r['credential_refs'].update(previous='x' * 129),
            lambda r: r.update(vault_state='definitely_changed'),
            lambda r: r.update(monitoring_state='probably_up'),
            lambda r: r.update(events={}),
            lambda r: r.update(events=[{'at': STAMP, 'phase': 'PRECHECK', 'operation': 'shell', 'device': 'R1',
                                        'result': 'PASS', 'error': None}]),
            lambda r: r.update(events=[{'at': STAMP, 'phase': 'PRECHECK', 'operation': 'verify', 'device': 'TEST',
                                        'result': 'PASS', 'error': None}]),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                record = example()
                mutate(record)
                with self.assertRaises(state.StateError):
                    state.validate_state(record)

    def test_unknown_secret_fields_and_raw_errors_are_never_serializable(self):
        marker = 'SYNTHETIC_DO_NOT_PERSIST!'
        for field in ('password', 'password_hash', 'token', 'authorization', 'private_key'):
            record = example()
            record[field] = marker
            with self.assertRaises(state.StateError) as result:
                state.validate_state(record)
            self.assertFalse(marker in str(result.exception))
        for container in ('devices', 'credential_refs', 'events'):
            record = example()
            if container == 'devices':
                record[container]['R1']['last_error'] = marker
            elif container == 'credential_refs':
                record[container]['password'] = marker
            else:
                record[container].append({'at': STAMP, 'phase': 'PRECHECK', 'operation': 'verify', 'device': 'R1',
                                          'result': 'FAIL', 'error': marker})
            with self.assertRaises(state.StateError) as result:
                state.validate_state(record)
            self.assertFalse(marker in str(result.exception))

    def test_event_phase_is_required_and_allowlisted(self):
        record = example()
        event = {'at': STAMP, 'phase': 'PRECHECK', 'operation': 'transition',
                 'device': None, 'result': 'INFO', 'error': None}
        record['events'] = [event]
        for phase in state.PHASES:
            event['phase'] = phase
            state.validate_state(record)
        event['phase'] = 'UNRECOGNIZED'
        with self.assertRaises(state.StateError):
            state.validate_state(record)
        del event['phase']
        with self.assertRaises(state.StateError):
            state.validate_state(record)

    def test_event_limit(self):
        record = example()
        event = {'at': STAMP, 'phase': 'PRECHECK', 'operation': 'verify', 'device': 'R1', 'result': 'PASS', 'error': None}
        record['events'] = [event] * state.MAX_EVENTS
        state.validate_state(record)
        record['events'].append(event)
        with self.assertRaises(state.StateError):
            state.validate_state(record)


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='netpilot-rotation-state-')
        self.base = Path(self.temporary.name)
        self.root = self.base / 'state' / 'rotation'
        self.store = state.JournalStore(self.root)
        self.record = example()
        self.network = patch.object(socket.socket, 'connect', side_effect=AssertionError('Offline tests prohibit network access.'))
        self.network.start()

    def tearDown(self):
        self.network.stop()
        self.temporary.cleanup()

    def _save(self, record=None):
        with self.store.lock():
            self.store.save(record or self.record)

    def _write_raw(self, content):
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.store.path.write_bytes(content)
        self.store.path.chmod(0o600)

    def test_absent_status_and_unlocked_save_do_not_create_storage(self):
        self.assertIsNone(self.store.load())
        with self.assertRaises(state.StateError):
            self.store.save(self.record)
        self.assertFalse(self.root.exists())

    def test_round_trip_permissions_restart_and_no_temporary_files(self):
        self._save()
        self.assertEqual(state.JournalStore(self.root).load(), self.record)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        for name in ('journal.json', 'rotation.lock'):
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o600)
        self.assertEqual({p.name for p in self.root.iterdir()}, {'journal.json', 'rotation.lock'})

    def test_lock_is_nonblocking_and_released_after_exception_without_unlink(self):
        other = state.JournalStore(self.root)
        with self.assertRaises(RuntimeError):
            with self.store.lock():
                inode = (self.root / 'rotation.lock').stat().st_ino
                with self.assertRaises(state.StateError):
                    with other.lock():
                        self.fail('A concurrent operation acquired the lock.')
                with self.assertRaises(state.StateError):
                    with self.store.lock():
                        self.fail('Nested locks must be rejected.')
                raise RuntimeError('synthetic interruption')
        with other.lock():
            self.assertEqual((self.root / 'rotation.lock').stat().st_ino, inode)
            other.save(self.record)

    @unittest.skipUnless(hasattr(os, 'fork'), 'Linux process-lock check')
    def test_lock_protects_against_separate_process(self):
        with self.store.lock():
            child = os.fork()
            if child == 0:
                try:
                    with state.JournalStore(self.root).lock():
                        os._exit(2)
                except state.StateError:
                    os._exit(0)
                except BaseException:
                    os._exit(3)
            _, result = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(result), 0)

    def test_save_requires_same_thread_that_holds_lock(self):
        outcomes = []
        def save_from_thread():
            try:
                self.store.save(self.record)
            except state.StateError:
                outcomes.append('blocked')
        with self.store.lock():
            worker = threading.Thread(target=save_from_thread)
            worker.start()
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(outcomes, ['blocked'])
        self.assertIsNone(self.store.load())

    def test_symlink_root_ancestor_and_journal_fail_closed(self):
        outside = self.base / 'outside'
        outside.mkdir(mode=0o700)
        self.root.parent.mkdir(mode=0o700)
        self.root.symlink_to(outside, target_is_directory=True)
        for method in ('load', 'lock'):
            with self.subTest(method=method), self.assertRaises(state.StateError):
                if method == 'load':
                    self.store.load()
                else:
                    with self.store.lock():
                        self.fail('Symlink root lock was accepted.')
        self.root.unlink()
        self.root.parent.rmdir()
        self.root.parent.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(state.StateError):
            self.store.load()
        self.root.parent.unlink()
        self._save()
        self.store.path.unlink()
        (outside / 'target').write_bytes(b'untouched')
        self.store.path.symlink_to(outside / 'target')
        with self.assertRaises(state.StateError):
            self.store.load()
        with self.store.lock(), self.assertRaises(state.StateError):
            self.store.save(self.record)
        self.assertEqual((outside / 'target').read_bytes(), b'untouched')

    def test_journal_hardlink_permissions_and_wrong_owner_rejected(self):
        self._save()
        os.link(self.store.path, self.base / 'second-name')
        with self.assertRaises(state.StateError):
            self.store.load()
        (self.base / 'second-name').unlink()
        self.store.path.chmod(0o644)
        with self.assertRaises(state.StateError):
            self.store.load()
        self.store.path.chmod(0o600)
        with patch.object(state.os, 'geteuid', return_value=os.geteuid() + 1):
            with self.assertRaises(state.StateError):
                self.store.load()
        self.root.chmod(0o750)
        with self.assertRaises(state.StateError):
            self.store.load()
        self.root.chmod(0o700)

    def test_lock_file_symlink_and_fifo_rejected_without_blocking(self):
        self.root.mkdir(parents=True, mode=0o700)
        lock = self.root / 'rotation.lock'
        lock.symlink_to(self.base / 'missing')
        with self.assertRaises(state.StateError):
            with self.store.lock():
                self.fail('Unsafe lock accepted.')
        lock.unlink()
        os.mkfifo(lock, 0o600)
        with self.assertRaises(state.StateError):
            with self.store.lock():
                self.fail('FIFO lock accepted.')
        lock.unlink()
        os.mkfifo(self.store.path, 0o600)
        with self.assertRaises(state.StateError):
            self.store.load()

    def test_corrupt_unknown_and_duplicate_json_fail_without_replacement(self):
        for raw in (b'{broken', b'null', b'{"password":"SYNTHETIC"}',
                    b'{"version":1,"version":1}', b'\xff'):
            with self.subTest(kind=raw[:1]):
                self._write_raw(raw)
                with self.assertRaises(state.StateError):
                    self.store.load()
                with self.store.lock(), self.assertRaises(state.StateError):
                    self.store.save(self.record)
                self.assertEqual(self.store.path.read_bytes(), raw)

    def test_invalid_new_state_preserves_prior_bytes(self):
        self._save()
        before = self.store.path.read_bytes()
        invalid = deepcopy(self.record)
        invalid['password'] = 'SYNTHETIC'
        with self.store.lock(), self.assertRaises(state.StateError):
            self.store.save(invalid)
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_replace_file_fsync_and_temporary_validation_failures_preserve_original(self):
        self._save()
        before = self.store.path.read_bytes()
        updated = deepcopy(self.record)
        updated['phase'] = 'PREPARED'
        for operation in ('replace', 'fsync', 'temporary-validation'):
            with self.subTest(operation=operation), self.store.lock():
                if operation == 'temporary-validation':
                    injected = patch.object(state, '_read_file', return_value=b'invalid')
                else:
                    injected = patch.object(state.os, operation, side_effect=OSError('SYNTHETIC_DIAGNOSTIC'))
                with injected, self.assertRaises(state.StateError) as result:
                    self.store.save(updated)
                self.assertFalse('SYNTHETIC_DIAGNOSTIC' in str(result.exception))
                self.assertEqual(self.store.path.read_bytes(), before)
                self.assertFalse(list(self.root.glob('.journal-*')))

    def test_post_replace_directory_fsync_failure_reports_uncertain_durability(self):
        self._save()
        updated = deepcopy(self.record)
        updated['phase'] = 'PREPARED'
        real_fsync = os.fsync
        def sync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError('SYNTHETIC_DIAGNOSTIC')
            return real_fsync(descriptor)
        with self.store.lock(), patch.object(state.os, 'fsync', side_effect=sync):
            with self.assertRaisesRegex(state.StateError, 'durability is uncertain'):
                self.store.save(updated)
        self.assertEqual(self.store.load(), updated)

    def test_changed_root_inode_blocks_save(self):
        self._save()
        with self.store.lock():
            moved = self.root.with_name('moved')
            self.root.rename(moved)
            self.root.mkdir(mode=0o700)
            with self.assertRaises(state.StateError):
                self.store.save(self.record)
            self.assertFalse(self.store.path.exists())
            self.assertTrue((moved / 'journal.json').is_file())

    def test_failed_archive_preserves_original_audit_before_clearing_active_record(self):
        failed = example('PARTIAL_FAILURE')
        failed['scope'] = list(state.FLEET)
        failed['events'] = [{'at': STAMP, 'phase': 'PARTIAL_FAILURE', 'operation': 'rotate',
                             'device': 'R1', 'result': 'FAIL', 'error': 'credentials'}]
        self._save(failed)
        before = self.store.path.read_bytes()
        with self.store.lock():
            self.store.archive_failed(failed)
            archive = self.root / 'history' / (failed['rotation_id'] + '.json')
            self.assertEqual(archive.read_bytes(), before)
            self.assertEqual(self.store.load(), failed)
            self.store.finish_failed(failed)
        self.assertIsNone(self.store.load())
        self.assertEqual(archive.read_bytes(), before)
        self.assertEqual(json.loads(archive.read_text())['phase'], 'PARTIAL_FAILURE')

    def test_failed_finalization_requires_lock_matching_record_and_failed_phase(self):
        self._save()
        with self.assertRaises(state.StateError):
            self.store.finish_failed(self.record)
        with self.store.lock():
            for record in (self.record, example('PARTIAL_FAILURE')):
                with self.subTest(phase=record['phase']), self.assertRaises(state.StateError):
                    self.store.finish_failed(record)
        self.assertEqual(self.store.load(), self.record)
        self.assertFalse((self.root / 'history').exists())

    def test_failed_archive_failure_never_clears_active_state(self):
        failed = example('RECOVERY_REQUIRED')
        self._save(failed)
        with self.store.lock(), patch.object(state.os, 'link', side_effect=OSError('synthetic')):
            with self.assertRaises(state.StateError):
                self.store.finish_failed(failed)
        self.assertEqual(self.store.load(), failed)

    def test_history_is_offline_and_validates_archived_record_identity(self):
        self.assertEqual(self.store.history(), [])
        self.assertFalse(self.root.exists())
        committed = example('COMMITTED')
        self._save(committed)
        with self.store.lock():
            self.store.archive_completed(committed)
        self.assertEqual(self.store.history(), [committed])
        archive = self.root / 'history' / (committed['rotation_id'] + '.json')
        archive.rename(archive.with_name('f' * 32 + '.json'))
        with self.assertRaises(state.StateError):
            self.store.history()

    def test_nested_operations_share_lock_but_other_stores_cannot_enter(self):
        other = state.JournalStore(self.root)
        with self.store.operation():
            with self.store.operation():
                self.store.save(self.record)
                with self.assertRaises(state.StateError):
                    with other.operation():
                        self.fail('Another operation acquired the active lock')
            with self.assertRaises(state.StateError):
                with other.operation():
                    self.fail('Nested exit released outer lock')
        with other.operation():
            self.assertEqual(other.load(), self.record)

    def test_terminal_archive_is_private_immutable_and_idempotent(self):
        completed = example('ROLLED_BACK')
        completed['ended_at'] = STAMP
        self._save(completed)
        with self.store.lock():
            self.store.archive_completed(completed)
            archive = self.root / 'history' / (completed['rotation_id'] + '.json')
            before = archive.read_bytes()
            inode = archive.stat().st_ino
            self.store.archive_completed(completed)
            self.assertEqual(archive.read_bytes(), before)
            self.assertEqual(archive.stat().st_ino, inode)
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(archive.parent.stat().st_mode), 0o700)
            self.assertEqual(self.store.load(), completed)
            new = example()
            new['rotation_id'] = '2' * 32
            self.store.save(new)
            self.assertEqual(archive.read_bytes(), before)
        self.assertEqual(self.store.load(), new)


    def test_archive_recovers_only_its_interrupted_publication_link(self):
        completed = example('COMMITTED')
        self._save(completed)
        with self.store.lock():
            self.store.archive_completed(completed)
            archive = self.root / 'history' / (completed['rotation_id'] + '.json')
            interrupted = archive.parent / ('.archive-' + '3' * 32 + '.tmp')
            os.link(archive, interrupted)
            self.store.archive_completed(completed)
            self.assertFalse(interrupted.exists())
            self.assertEqual(archive.stat().st_nlink, 1)
            outside_link = self.base / 'unrelated-link'
            os.link(archive, outside_link)
            with self.assertRaises(state.StateError):
                self.store.archive_completed(completed)
            self.assertTrue(outside_link.exists())


    def test_archive_requires_active_lock_terminal_phase_and_matching_current(self):
        self._save()
        with self.assertRaises(state.StateError):
            self.store.archive_completed(self.record)
        with self.store.lock():
            with self.assertRaises(state.StateError):
                self.store.archive_completed(self.record)
            with self.assertRaises(state.StateError):
                self.store.archive_completed(example('COMMITTED'))
        self.assertFalse((self.root / 'history').exists())

    def test_conflicting_existing_archive_never_overwritten(self):
        completed = example('COMMITTED')
        self._save(completed)
        with self.store.lock():
            self.store.archive_completed(completed)
            archive = self.root / 'history' / (completed['rotation_id'] + '.json')
            altered = deepcopy(completed)
            altered['monitoring_state'] = 'failed'
            archive.write_text(json.dumps(altered))
            before = archive.read_bytes()
            with self.assertRaises(state.StateError):
                self.store.archive_completed(completed)
            self.assertEqual(archive.read_bytes(), before)
            self.assertEqual(self.store.load(), completed)

    def test_archive_publication_failure_preserves_active_journal_and_cleans_temp(self):
        completed = example('COMMITTED')
        self._save(completed)
        before = self.store.path.read_bytes()
        with self.store.lock(), patch.object(state.os, 'link', side_effect=OSError('synthetic')):
            with self.assertRaises(state.StateError):
                self.store.archive_completed(completed)
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertEqual(list((self.root / 'history').iterdir()), [])

    def test_history_symlink_rejected_without_writing_target(self):
        completed = example('COMMITTED')
        self._save(completed)
        outside = self.base / 'outside'
        outside.mkdir(mode=0o700)
        (self.root / 'history').symlink_to(outside, target_is_directory=True)
        with self.store.lock(), self.assertRaises(state.StateError):
            self.store.archive_completed(completed)
        self.assertEqual(list(outside.iterdir()), [])


    def test_finish_completed_archives_before_removal_and_preserves_other_history(self):
        older = example('COMMITTED')
        older['rotation_id'] = '2' * 32
        self._save(older)
        with self.store.lock():
            self.store.archive_completed(older)
        prior = self.root / 'history' / (older['rotation_id'] + '.json')
        prior_bytes, prior_inode = prior.read_bytes(), prior.stat().st_ino
        completed = example('ROLLED_BACK')
        completed['ended_at'] = STAMP
        self._save(completed)
        active_bytes = self.store.path.read_bytes()
        archive = self.root / 'history' / (completed['rotation_id'] + '.json')
        lock_inode = (self.root / 'rotation.lock').stat().st_ino
        real_unlink = os.unlink
        removals = []
        def remove(name, *args, **kwargs):
            if name == 'journal.json':
                self.assertEqual(archive.read_bytes(), active_bytes)
                self.assertEqual(self.store.load(), completed)
                removals.append(name)
            return real_unlink(name, *args, **kwargs)
        with self.store.lock(), patch.object(state.os, 'unlink', side_effect=remove):
            self.store.finish_completed(completed)
        self.assertEqual(removals, ['journal.json'])
        self.assertIsNone(self.store.load())
        self.assertEqual(json.loads(archive.read_text()), completed)
        self.assertEqual((prior.read_bytes(), prior.stat().st_ino), (prior_bytes, prior_inode))
        self.assertEqual((self.root / 'rotation.lock').stat().st_ino, lock_inode)

    def test_finish_completed_requires_lock_terminal_phase_and_matching_current(self):
        self._save()
        before = self.store.path.read_bytes()
        with self.assertRaises(state.StateError):
            self.store.finish_completed(self.record)
        with self.store.lock():
            for candidate in (self.record, example('ROLLED_BACK')):
                with self.subTest(phase=candidate['phase']), self.assertRaises(state.StateError):
                    self.store.finish_completed(candidate)
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertFalse((self.root / 'history').exists())

    def test_finish_completed_refuses_journal_changed_after_archive(self):
        completed, replacement = example('ROLLED_BACK'), example()
        replacement['rotation_id'] = '2' * 32
        self._save(completed)
        real_archive = self.store.archive_completed
        def archive_then_change(record):
            real_archive(record)
            self.store.save(replacement)
        with self.store.lock(), patch.object(self.store, 'archive_completed', side_effect=archive_then_change):
            with self.assertRaises(state.StateError):
                self.store.finish_completed(completed)
        self.assertEqual(self.store.load(), replacement)
        archive = self.root / 'history' / (completed['rotation_id'] + '.json')
        self.assertEqual(json.loads(archive.read_text()), completed)

    def test_finish_completed_archive_failure_never_removes_active_journal(self):
        completed = example('ROLLED_BACK')
        self._save(completed)
        before = self.store.path.read_bytes()
        with self.store.lock(), patch.object(state.os, 'link', side_effect=OSError('synthetic')):
            with self.assertRaises(state.StateError):
                self.store.finish_completed(completed)
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertEqual(list((self.root / 'history').iterdir()), [])

    def test_finish_completed_post_removal_fsync_failure_preserves_history(self):
        completed = example('ROLLED_BACK')
        self._save(completed)
        real_fsync = os.fsync
        def sync(descriptor):
            if descriptor == self.store._directory_fd and not self.store.path.exists():
                raise OSError('synthetic cleanup diagnostic')
            return real_fsync(descriptor)
        with self.store.lock(), patch.object(state.os, 'fsync', side_effect=sync):
            with self.assertRaisesRegex(state.StateError, 'history is preserved') as caught:
                self.store.finish_completed(completed)
        self.assertNotIn('synthetic cleanup diagnostic', str(caught.exception))
        archive = self.root / 'history' / (completed['rotation_id'] + '.json')
        self.assertEqual(json.loads(archive.read_text()), completed)
        self.assertIsNone(self.store.load())


if __name__ == '__main__':
    unittest.main()
