"""Exact external-fixture coverage inputs; no shell evaluation or invented counters."""
import base64
import hashlib
import os
from pathlib import Path
import re
import shlex


MAX_PROFILE_BYTES = 16 * 1024 * 1024


def instrumented_environment(output, inherited):
    """Read cargo-llvm-cov's default shell-escaped KEY=VALUE output as data."""
    values = {}
    for line in output.splitlines():
        fields = shlex.split(line)
        if len(fields) != 1 or '=' not in fields[0]:
            raise RuntimeError('unexpected coverage environment record')
        name, value = fields[0].split('=', 1)
        if not re.fullmatch(r'[A-Z_][A-Z0-9_]*', name) or name in values:
            raise RuntimeError('invalid or repeated coverage environment key')
        values[name] = value
    profile = Path(values.get('LLVM_PROFILE_FILE', ''))
    if not profile.is_absolute() or profile.suffix != '.profraw':
        raise RuntimeError('coverage setup must supply an absolute profile path')
    # show-env cannot unset inherited variables. Do not let a higher-priority
    # global Rust flag silently override target-only Wasm instrumentation.
    if inherited.get('RUSTFLAGS') or inherited.get('CARGO_ENCODED_RUSTFLAGS'):
        raise RuntimeError('global Rust flags conflict with target-only coverage')
    return dict(inherited, **values)


def save_profiles(captures, profile_pattern, artifacts):
    """Retain each navigation's real counters after both native checks succeed."""
    if len(captures) != 3:
        raise RuntimeError('two ceremony profiles and the insecure platform profile are required')
    decoded = []
    for phase, capture in enumerate(captures, 1):
        if not isinstance(capture, dict) or set(capture) != {'profile', 'signature'}:
            raise RuntimeError('missing actual browser profile')
        encoded, signature = capture['profile'], capture['signature']
        if (not isinstance(signature, str) or not re.fullmatch(r'[0-9]{1,20}', signature)
                or int(signature) > 2**64 - 1):
            raise RuntimeError('invalid actual Wasm module signature')
        if not isinstance(encoded, str) or not 0 < len(encoded) <= 4 * ((MAX_PROFILE_BYTES + 2) // 3):
            raise RuntimeError('empty or oversized browser profile')
        raw = base64.b64decode(encoded, validate=True)
        if not 0 < len(raw) <= MAX_PROFILE_BYTES:
            raise RuntimeError('empty or oversized decoded browser profile')
        decoded.append((phase, signature, raw))
    if any(item[1] != decoded[0][1] for item in decoded):
        raise RuntimeError('browser navigations executed different Wasm modules')
    profile_root = Path(profile_pattern).parent.resolve(strict=True)
    retained = Path(artifacts) / 'https-loopback-profiles'
    retained.mkdir()
    receipts = []
    for phase, signature, raw in decoded:
        name = f'cpky-loopback-{os.getpid()}-{phase}-{signature}.profraw'
        # The exact coverage target directory is selected by cargo-llvm-cov.
        # Exclusive creation refuses old data; LLVM later validates raw counters.
        with (profile_root / name).open('xb') as output:
            output.write(raw)
        with (retained / name).open('xb') as output:
            output.write(raw)
        receipts.append(dict(phase=phase, module_signature=signature,
                             path=str(Path(retained.name) / name), bytes=len(raw),
                             sha256=hashlib.sha256(raw).hexdigest()))
    return receipts
