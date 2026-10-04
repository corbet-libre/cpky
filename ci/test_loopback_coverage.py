"""Evidence-handling refusal vectors, not substitutes for actual LLVM/browser runs."""
import base64
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from loopback_coverage import instrumented_environment, save_profiles


class CoverageInputs(unittest.TestCase):
    def test_upstream_wrapper_exports_preserve_encoded_flags(self):
        # cargo-llvm-cov 0.9.0 src/wrapper.rs uses these private environment
        # names. Their leading underscores are valid and required for coverage.
        flags = '-C\x1finstrument-coverage\x1f-Z\x1fcoverage-options=branch'
        parsed = instrumented_environment(
            "LLVM_PROFILE_FILE=/tmp/coverage/%m.profraw\n"
            "__CARGO_LLVM_COV_RUSTC_WRAPPER=1\n"
            f"__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS='{flags}'\n"
            "__CARGO_LLVM_COV_RUSTC_WRAPPER_COVERAGE_TARGET=wasm32-unknown-unknown\n",
            {})
        self.assertEqual(parsed['__CARGO_LLVM_COV_RUSTC_WRAPPER'], '1')
        self.assertEqual(parsed['__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS'], flags)
        self.assertEqual(parsed['__CARGO_LLVM_COV_RUSTC_WRAPPER_COVERAGE_TARGET'],
                         'wasm32-unknown-unknown')

    def test_environment_preserves_quoted_values_without_execution(self):
        with tempfile.TemporaryDirectory() as scratch:
            marker = Path(scratch) / 'must-not-exist'
            value = f'$(touch {marker})'
            parsed = instrumented_environment(
                f"LLVM_PROFILE_FILE='{scratch}/target with spaces/%m.profraw'\n"
                f"RUSTC_WRAPPER='{value}'\n", {'PATH': '/tools'})
            self.assertEqual(parsed['RUSTC_WRAPPER'], value)
            self.assertEqual(parsed['PATH'], '/tools')
            self.assertFalse(marker.exists())

    def test_missing_repeated_and_malformed_environment_refuse(self):
        valid = 'LLVM_PROFILE_FILE=/tmp/actual-%m.profraw\n'
        for output in ['', 'LLVM_PROFILE_FILE=relative.profraw\n',
                       'LLVM_PROFILE_FILE=/tmp/wrong.txt\n', valid + valid,
                       valid + 'echo malicious\n', valid + 'bad-key=value\n',
                       valid + 'llvm_profile_file=value\n',
                       valid + 'PATH="unterminated\n']:
            with self.subTest(output=output), self.assertRaises((RuntimeError, ValueError)):
                instrumented_environment(output, {})
        for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS']:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                instrumented_environment(valid, {key: '-C opt-level=3'})

    def test_all_three_profiles_are_retained_exactly_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            target, artifacts = root / 'target', root / 'artifacts'
            target.mkdir()
            artifacts.mkdir()
            # These opaque bytes test evidence copying only. LLVM validation and
            # actual browser counters are required by the real acceptance phase.
            payloads = [b'first-profile-fixture', b'second-profile-fixture',
                        b'insecure-profile-fixture']
            captures = [dict(profile=base64.b64encode(raw).decode(), signature='17')
                        for raw in payloads]
            receipts = save_profiles(captures, target / '%m.profraw', artifacts)
            for receipt, raw in zip(receipts, payloads, strict=True):
                self.assertEqual((artifacts / receipt['path']).read_bytes(), raw)
                self.assertEqual((target / Path(receipt['path']).name).read_bytes(), raw)
                self.assertEqual(receipt['sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(receipt['bytes'], len(raw))
            before = {p.name: p.read_bytes() for p in target.iterdir()}
            with self.assertRaises(FileExistsError):
                save_profiles(captures, target / '%m.profraw', artifacts)
            self.assertEqual({p.name: p.read_bytes() for p in target.iterdir()}, before)

    def test_missing_corrupt_and_cross_module_profiles_write_nothing(self):
        valid = dict(profile=base64.b64encode(b'profile-fixture').decode(), signature='17')
        invalid = [None, {}, {'failed': True}, dict(valid, extra='field'),
                   dict(valid, profile=''), dict(valid, profile='%%%'),
                   dict(valid, profile=12), dict(valid, signature=17),
                   dict(valid, signature='../elsewhere'), dict(valid, signature=''),
                   dict(valid, signature='1' * 21), dict(valid, signature=str(2**64)),
                   dict(valid, signature='18')]
        for bad in invalid:
            with tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                with self.subTest(bad=bad), self.assertRaises((RuntimeError, ValueError)):
                    save_profiles([valid, valid, bad], root / '%m.profraw', root)
                self.assertEqual(list(root.iterdir()), [])
        for count in [0, 1, 2, 4]:
            with self.subTest(count=count), self.assertRaises(RuntimeError):
                save_profiles([valid] * count, '/unused/%m.profraw', '/unused')

    def test_stale_target_profile_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            old = root / f'cpky-loopback-{os.getpid()}-1-42.profraw'
            old.write_bytes(b'existing-profile-fixture')
            capture = dict(profile=base64.b64encode(b'new-profile-fixture').decode(), signature='42')
            with self.assertRaises(FileExistsError):
                save_profiles([capture, capture, capture], root / '%m.profraw', root)
            self.assertEqual(old.read_bytes(), b'existing-profile-fixture')
            self.assertEqual(list((root / 'https-loopback-profiles').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
