"""Fail-closed checks for incomplete, damaged and uncovered report inputs."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import tempfile

script = Path(__file__).with_name('check-source-coverage.py')
spec = importlib.util.spec_from_file_location('coverage_gate', script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    source = root / 'src/lib.rs'
    source.parent.mkdir()
    source.write_text('pub fn choose(value: bool) -> bool { value }\n')
    report = {'type': 'llvm.coverage.json.export', 'data': [{'files': [{
        'filename': str(source), 'branches': [[1, 1, 1, 2, 1, 1]],
        'summary': {'lines': {'count': 1, 'covered': 1},
                    'branches': {'count': 2, 'covered': 2}},
    }]}]}
    valid = (f'SF:{source}\nDA:1,2\nBRDA:1,0,0,1\nBRDA:1,0,1,1\n'
             'LF:1\nLH:1\nBRF:2\nBRH:2\nend_of_record\n')
    cases = [('complete', valid, report, True)]
    for name, damaged in [
        ('empty', ''),
        ('truncated', valid.replace('end_of_record\n', '')),
        ('missing line', valid.replace('DA:1,2\n', '')),
        ('missing branch', valid.replace('BRDA:1,0,0,1\n', '')),
        ('duplicate file', valid + valid),
        ('duplicate line', valid.replace('DA:1,2\n', 'DA:1,2\nDA:1,2\n')),
        ('duplicate branch', valid.replace('BRDA:1,0,0,1\n', 'BRDA:1,0,0,1\nBRDA:1,0,0,1\n')),
        ('missing summary', valid.replace('LF:1\n', '')),
        ('inconsistent summary', valid.replace('LF:1\n', 'LF:2\n')),
        ('unknown branch', valid.replace('BRDA:1,0,0,1', 'BRDA:1,0,0,-')),
        ('uncovered branch', valid.replace('BRDA:1,0,0,1', 'BRDA:1,0,0,0')),
        ('uncovered line', valid.replace('DA:1,2', 'DA:1,0')),
        ('negative line', valid.replace('DA:1,2', 'DA:1,-1')),
        ('nonproduction source', valid.replace('/src/', '/tests/')),
    ]:
        cases.append((name, damaged, report, False))
    other = copy.deepcopy(report)
    other['data'][0]['files'].append(dict(other['data'][0]['files'][0], filename=str(root/'src/other.rs')))
    cases.append(('missing file inventory', valid, other, False))
    cases.append(('missing companion', valid, {}, False))
    for name, lcov, raw, accepted in cases:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                module.check(lcov, raw, root)
            result = True
        except (ValueError, KeyError, TypeError):
            result = False
        assert result == accepted, name
    print(f'Coverage report refusal checks: {len(cases)} passed')
