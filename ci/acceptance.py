#!/usr/bin/env python3
"""Fixed complete Passkeys gates, after the shared one-lock resolver."""
import hashlib
import json
import os
import re
import tarfile
import urllib.request
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib


ROOT = Path.cwd().resolve()
POLICY = [sys.executable, '.github/scripts/check-first-party.py', '--archive']
COVERAGE_SETUP = '/nix/store/hddk15hgahw73wk2hdfir1v0si7vcs61-cmty-wasm-coverage-tools/share/cmty-wasm-coverage-tools/setup.sh'
COVERAGE_SHA = 'b169bbb42929bbb673f1eda497d98cae1891803c4c6285471f8735d880047e3b'
PHASES = ('native', 'wasm', 'browser', 'coverage', 'dependency-policy')


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()



def log_tail(path):
    """Retain full files externally; cap both total output and every console line."""
    path = Path(path)
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - 16384))
        tail = stream.read().decode('utf-8', errors='replace')
    print(json.dumps(dict(log=str(path), sha256=digest(path), bytes=path.stat().st_size)), flush=True)
    for line in tail.splitlines()[-80:]:
        print(line[:512], flush=True)


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def nightly(command, **kwargs):
    if digest(COVERAGE_SETUP) != COVERAGE_SHA:
        raise RuntimeError('coverage setup differs from reviewed tool receipt')
    return run(['bash', '-euo', 'pipefail', '-c',
                '. "$1"; shift; exec "$@"', 'coverage', COVERAGE_SETUP, *command], **kwargs)


def wasm_cc():
    """Absolute wasm32 C compiler from the qualified setup only (no PATH fallback).

    Stable browser tests build the owned coverage runtime's C build script for
    wasm32 (minicov hard-codes the compiler name `clang`), which needs the same
    compiler the coverage phase already uses; its directory goes in front of PATH
    for that one command only.
    """
    result = nightly(['bash', '-euo', 'pipefail', '-c', 'printf "%s\\n" "$CC_wasm32_unknown_unknown"'],
                     capture_output=True, text=True)
    lines = result.stdout.strip().splitlines()
    if not lines or not lines[-1].startswith('/') or not os.access(lines[-1], os.X_OK):
        raise RuntimeError('the qualified wasm32 C compiler is not an executable absolute path')
    return lines[-1]


def wasm_target(compiler, **kwargs):
    result = compiler(['rustc', '--print', 'target-libdir', '--target', 'wasm32-unknown-unknown'],
                      capture_output=True, text=True, **kwargs)
    if not list(Path(result.stdout.strip()).glob('libstd-*')):
        raise RuntimeError('the selected compiler lacks its actual Wasm standard library')


def browser_tools():
    driver = os.environ.get('CHROMEDRIVER') or shutil.which('chromedriver')
    browser = os.environ.get('CHROME_BIN') or shutil.which('chromium') or shutil.which('google-chrome')
    if not driver or not browser:
        raise RuntimeError('installed browser and matching driver are required')
    return browser, driver


def acquire_runner(artifacts):
    # Only the fresh candidate lock chooses this maintained tooling version.
    packages = tomllib.loads(Path('Cargo.lock').read_text())['package']
    versions = {p['version'] for p in packages if p['name'] == 'wasm-bindgen'}
    if len(versions) != 1:
        raise RuntimeError('one candidate wasm-bindgen version is required')
    version = versions.pop()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise RuntimeError('unexpected maintained runner version')
    root = artifacts / 'wasm-runner'
    root.mkdir()
    name = f'wasm-bindgen-{version}-x86_64-unknown-linux-musl.tar.gz'
    base = f'https://github.com/wasm-bindgen/wasm-bindgen/releases/download/{version}'
    for suffix, limit in [('', 256 * 1024 * 1024), ('.sha256sum', 4096)]:
        request = urllib.request.Request(base + '/' + name + suffix,
                                         headers={'User-Agent': 'ci-dependency-fetch/1.0'})
        with urllib.request.urlopen(request, timeout=120) as response, (root / (name + suffix)).open('xb') as target:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > limit:
                    raise RuntimeError('maintained runner download exceeds bound')
                target.write(chunk)
    expected = (root / (name + '.sha256sum')).read_text().split()[0]
    archive = root / name
    if not re.fullmatch('[0-9a-f]{64}', expected) or digest(archive) != expected:
        raise RuntimeError('maintained runner release SHA mismatch')
    binaries = {}
    with tarfile.open(archive, 'r:gz') as package:
        for tool in ['wasm-bindgen', 'wasm-bindgen-test-runner']:
            members = [m for m in package.getmembers()
                       if m.name == name.removesuffix('.tar.gz') + '/' + tool]
            if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= 128 * 1024 * 1024:
                raise RuntimeError('invalid maintained runner archive member')
            target = root / tool
            with package.extractfile(members[0]) as source, target.open('xb') as destination:
                shutil.copyfileobj(source, destination)
            target.chmod(0o700)
            binaries[tool] = digest(target)
    os.environ['PATH'] = str(root) + os.pathsep + os.environ['PATH']
    with (artifacts / 'runner-version.txt').open('w') as stream:
        for tool in binaries:
            output = run([tool, '--version'], capture_output=True, text=True).stdout.strip()
            if output.split()[-1] != version:
                raise RuntimeError('downloaded Wasm runner differs from the candidate lock')
            stream.write(output + '\n')
    (artifacts / 'runner-artifact.json').write_text(json.dumps(dict(
        lock_sha256=digest('Cargo.lock'), version=version, source=base + '/' + name,
        archive='wasm-runner/' + name, sha256=expected,
        checksum='wasm-runner/' + name + '.sha256sum',
        checksum_sha256=digest(root / (name + '.sha256sum')), binaries=binaries,
    ), indent=2) + '\n')


def metadata(artifacts, name):
    destination = artifacts / (name + '-dependency-metadata.json')
    with destination.open('w') as stream:
        run(['cargo', 'metadata', '--locked', '--all-features', '--format-version', '1'], stdout=stream)
    run([*POLICY, '--metadata', str(destination)])


def preflight(artifacts):
    before = digest('Cargo.lock')
    browser, driver = browser_tools()
    wasm_target(run)
    wasm_target(nightly)
    run([sys.executable, '-c', 'import selenium, ssl, tarfile, urllib.request; ssl.create_default_context()'])
    with (artifacts / 'tool-versions.txt').open('w') as stream:
        for command in [['rustc', '--version', '--verbose'], ['cargo', '--version'],
                        ['cargo', 'deny', '--version'], [browser, '--version'], [driver, '--version']]:
            run(command, stdout=stream, stderr=subprocess.STDOUT)
        nightly(['bash', '-euo', 'pipefail', '-c', '"$CC_wasm32_unknown_unknown" --version'],
                stdout=stream, stderr=subprocess.STDOUT)
        nightly(['rustc', '--version', '--verbose'], stdout=stream, stderr=subprocess.STDOUT)
        nightly(['cargo', 'llvm-cov', '--version'], stdout=stream, stderr=subprocess.STDOUT)
        nightly(['bash', '-euo', 'pipefail', '-c', '"$LLVM_COV" --version; "$LLVM_PROFDATA" --version'],
                stdout=stream, stderr=subprocess.STDOUT)
    metadata(artifacts, 'baseline')
    run([sys.executable, '.github/scripts/test-source-coverage.py'])
    run([sys.executable, 'ci/test_loopback_coverage.py'])
    if digest('Cargo.lock') != before:
        raise RuntimeError('preflight changed the lock')


def uncovered(lcov, stream):
    """Print compact per-file uncovered ranges; the gate itself prints one long line."""
    current = None
    found = {'lines': {}, 'branches': {}}
    for record in Path(lcov).read_text().splitlines():
        if record.startswith('SF:'):
            current = record[3:]
        elif record.startswith('DA:'):
            number, count = record[3:].split(',')[:2]
            if int(count) == 0:
                found['lines'].setdefault(current, set()).add(int(number))
        elif record.startswith('BRDA:'):
            number, _block, _branch, taken = record[5:].split(',')[:4]
            if taken in ('-', '0'):
                found['branches'].setdefault(current, set()).add(int(number))
    for kind, table in found.items():
        for name, numbers in sorted(table.items()):
            spans, start, previous = [], None, None
            for number in sorted(numbers):
                if start is None:
                    start = previous = number
                elif number == previous + 1:
                    previous = number
                else:
                    spans.append((start, previous))
                    start = previous = number
            spans.append((start, previous))
            text = ','.join(str(a) if a == b else f'{a}-{b}' for a, b in spans)
            print(f'UNCOVERED {kind} {name}: {text}', file=stream, flush=True)


def checked_coverage(lcov, report, stream):
    try:
        run([sys.executable, '.github/scripts/check-source-coverage.py', str(lcov), str(report)],
            stdout=stream, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        uncovered(lcov, stream)
        raise


def coverage(artifacts, stream):
    common = ['--locked', '--branch', '--all-features', '--ignore-filename-regex', '/tests/']
    nightly(['cargo', 'llvm-cov', *common, '--json', '--output-path', str(artifacts / 'coverage.json')],
            stdout=stream, stderr=subprocess.STDOUT)
    for kind in ['lcov', 'text']:
        suffix = 'txt' if kind == 'text' else kind
        nightly(['cargo', 'llvm-cov', 'report', '--' + kind, '--output-path',
                 str(artifacts / ('coverage.' + suffix)), '--ignore-filename-regex', '/tests/'],
                stdout=stream, stderr=subprocess.STDOUT)
    checked_coverage(artifacts / 'coverage.lcov', artifacts / 'coverage.json', stream)
    env = dict(os.environ, CPKY_COVERAGE='1', WASM_BINDGEN_TEST_ONLY_WEB='1',
               WASM_BINDGEN_SPLIT_LINKED_MODULES='1',
               CARGO_LLVM_COV_TARGET_DIR=str(Path(os.environ['CARGO_TARGET_DIR']) / 'llvm-cov-target'),
               CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER='python3 .github/scripts/browser-runner.py',
               CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='-Zno-profiler-runtime -Clink-args=--no-gc-sections --cfg=owned_browser_coverage')
    nightly(['cargo', 'llvm-cov', 'test', *common, '--lib', '--coverage-target-only',
             '--target', 'wasm32-unknown-unknown', '--lcov', '--output-path', str(artifacts / 'wasm-coverage.lcov')],
            env=env, stdout=stream, stderr=subprocess.STDOUT)
    nightly([sys.executable, 'ci/https-loopback.py', '--coverage'],
            env=env, stdout=stream, stderr=subprocess.STDOUT)
    # Re-export every format after the external fixture contributes its counters.
    # The strict checker must compare LCOV and JSON from the same merged input.
    for kind in ['lcov', 'json', 'text']:
        suffix = 'txt' if kind == 'text' else kind
        nightly(['cargo', 'llvm-cov', 'report', '--target', 'wasm32-unknown-unknown',
                 '--coverage-target-only', '--' + kind, '--output-path',
                 str(artifacts / ('wasm-coverage.' + suffix)), '--ignore-filename-regex', '/tests/'],
                env=env, stdout=stream, stderr=subprocess.STDOUT)
    checked_coverage(artifacts / 'wasm-coverage.lcov', artifacts / 'wasm-coverage.json', stream)


def acceptance(artifacts):
    acquire_runner(artifacts)  # Before owner compilation, from the candidate lock.
    metadata(artifacts, 'resolved')
    lock = digest('Cargo.lock')
    phases = []
    phase_file = artifacts / 'phases.json'
    if phase_file.exists():
        raise RuntimeError('acceptance artifacts must be new for this execution')
    phase_file.write_text('[]\n')
    for phase in PHASES:
        before = digest('Cargo.lock')
        if before != lock:
            raise RuntimeError('phase input lock changed')
        log = artifacts / (phase + '.log')
        try:
            with log.open('w') as stream:
                if phase == 'native':
                    run(['bash', 'ci/native-check.sh'], stdout=stream, stderr=subprocess.STDOUT)
                elif phase == 'wasm':
                    run(['cargo', 'clippy', '--locked', '--target', 'wasm32-unknown-unknown',
                         '--all-features', '--lib', '--', '-D', 'warnings'], stdout=stream, stderr=subprocess.STDOUT)
                elif phase == 'browser':
                    env = dict(os.environ, CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER='python3 .github/scripts/browser-runner.py',
                               WASM_BINDGEN_USE_BROWSER='1', WASM_BINDGEN_TEST_TIMEOUT='120',
                               CC_wasm32_unknown_unknown=wasm_cc())
                    env['PATH'] = os.path.dirname(env['CC_wasm32_unknown_unknown']) + os.pathsep + env['PATH']
                    run(['cargo', 'test', '--locked', '--target', 'wasm32-unknown-unknown', '--all-features', '--lib'],
                        env=env, stdout=stream, stderr=subprocess.STDOUT)
                    run([sys.executable, 'ci/https-loopback.py'], stdout=stream, stderr=subprocess.STDOUT)
                elif phase == 'coverage':
                    coverage(artifacts, stream)
                else:
                    run(POLICY, stdout=stream, stderr=subprocess.STDOUT)
                    run(['cargo', 'deny', '--locked', 'check', 'advisories'], stdout=stream, stderr=subprocess.STDOUT)
        except (subprocess.CalledProcessError, RuntimeError) as error:
            phases.append(dict(name=phase, status='failed', lock_before=before,
                               lock_after=digest('Cargo.lock'), log=log.name,
                               exit_code=getattr(error, 'returncode', 1)))
            phase_file.write_text(json.dumps(phases, indent=2) + '\n')
            log_tail(log)
            raise
        after = digest('Cargo.lock')
        if after != before:
            raise RuntimeError('phase changed the resolved lock')
        phases.append(dict(name=phase, status='passed', lock_before=before, lock_after=after, log=log.name))
        phase_file.write_text(json.dumps(phases, indent=2) + '\n')
        log_tail(log)


def main():
    if os.environ.get('CI') != 'crow' or os.environ.get('CHECKS') or len(sys.argv) != 2:
        raise RuntimeError('fixed Crow acceptance context is required')
    artifacts = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
    if artifacts == ROOT or ROOT in artifacts.parents:
        raise RuntimeError('artifacts must be outside immutable source')
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    if sys.argv[1] == 'preflight':
        preflight(artifacts)
    elif sys.argv[1] == 'acceptance':
        acceptance(artifacts)
    else:
        raise RuntimeError('unknown fixed acceptance phase')


if __name__ == '__main__':
    main()
