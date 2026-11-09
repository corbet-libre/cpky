#!/usr/bin/env python3
"""Require main declarations and one resolved revision per first-party crate."""
import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

FIRST_PARTY = re.compile(r"^(?:git\+)?https://(?:github\.com/(?:corbet-(?:foss|libs)|cmtymeet)|git\.corbet\.ch/(?:corbet-(?:foss|libs|libre|fsl)|cmty(?:meet|mt)))/")
SHA = re.compile(r"^[0-9a-f]{40}$")


def check_lock(packages):
    names = {p['name'] for p in packages if FIRST_PARTY.match(p.get('source') or '')}
    for name in names:
        entries = [p for p in packages if p['name'] == name]
        if len(entries) != 1:
            raise ValueError(f'Duplicate first-party crate: {name}')
        source = urlsplit(entries[0]['source'].removeprefix('git+'))
        query = parse_qs(source.query, keep_blank_values=True)
        if not SHA.fullmatch(source.fragment):
            raise ValueError(f'Missing resolved revision for {name}')
        if query != {'branch': ['main']}:
            raise ValueError(f'Invalid first-party source selector for {name}')


def check_manifest(value):
    if isinstance(value, dict):
        if FIRST_PARTY.match(value.get('git', '')):
            if value.get('branch') != 'main' or {'rev', 'tag'}.intersection(value):
                raise ValueError('First-party dependency must declare branch = "main"')
        for item in value.values():
            check_manifest(item)
    elif isinstance(value, list):
        for item in value:
            check_manifest(item)


def rejects(function, value):
    try:
        function(value)
    except ValueError:
        return
    raise AssertionError(f'Invalid input accepted: {value!r}')


def self_test():
    repo = 'https://github.com/corbet-foss/example'
    source = 'git+' + repo + '?branch=main#' + 'a' * 40
    package = {'name': 'example', 'source': source}
    check_lock([package])
    check_lock([{'name': 'local'}, {'name': 'workspace', 'source': None}])
    rejects(check_lock, [dict(package, source='git+' + repo + '?rev=' + 'a' * 40 + '#' + 'a' * 40)])
    for packages in ([package, package], [package, {'name': 'example'}],
                     [package, dict(package, source=source[:-1] + 'b')],
                     [dict(package, source=source.replace('main', 'develop'))],
                     [dict(package, source=source.replace('branch=main', 'tag=v1'))],
                     [dict(package, source=source.replace('branch=main', 'rev=' + 'b' * 40))],
                     [dict(package, source=source.replace('#' + 'a' * 40, '#short'))],
                     [dict(package, source=source.replace('branch=main', 'branch=main&branch=main'))]):
        rejects(check_lock, packages)
    for declaration in ({'git': repo}, {'git': repo, 'rev': 'a' * 40},
                        {'git': repo, 'branch': 'other'},
                        {'git': repo, 'branch': 'main', 'rev': 'a' * 40},
                        {'git': repo, 'branch': 'main', 'tag': 'v1'}):
        rejects(check_manifest, {'target': {'cfg(wasm)': {'dependencies': {'alias': declaration}}}})
    check_manifest({'workspace': {'dependencies': {'alias': {'git': repo, 'package': 'example', 'branch': 'main'}}}})


def check_first_party_orgs():
    """Every current owner resolves on the canonical forge; github.com keeps its former owners."""
    for owner in ('corbet-foss', 'corbet-libs', 'corbet-libre', 'corbet-fsl',
                  'cmtymeet', 'cmtymt'):
        url = f'https://git.corbet.ch/{owner}/example'
        if not FIRST_PARTY.match(url):
            raise AssertionError(f'First-party owner rejected: {url}')
    for url in ('https://git.corbet.ch.evil.test/corbet-libre/example',
                'https://user@git.corbet.ch/corbet-libre/example',
                'https://git.corbet.ch:443/corbet-libre/example',
                'https://git.corbet.ch/corbet-libre.evil/example',
                'https://github.com/corbet-libre/example',
                'https://github.com/corbet-fsl/example',
                'https://github.com/cmtymt/example'):
        if FIRST_PARTY.match(url):
            raise AssertionError(f'Invalid first-party owner accepted: {url}')

if __name__ == '__main__':
    check_first_party_orgs()
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--archive', action='store_true')
    parser.add_argument('--metadata', type=Path)
    args = parser.parse_args()
    self_test()
    if not args.self_test:
        if args.archive:
            paths = {str(p) for p in Path('.').rglob('Cargo.toml')
                     if not {'target', '.git', 'node_modules'}.intersection(p.parts)}
        else:
            paths = set(subprocess.check_output(['git', 'ls-files', '-z'], text=True).split('\0'))
        paths.add('Cargo.lock')
        for name in sorted(paths):
            path = Path(name)
            if path.name == 'Cargo.toml':
                check_manifest(tomllib.loads(path.read_text()))
            elif path.name == 'Cargo.lock':
                check_lock(tomllib.loads(path.read_text())['package'])
        if args.metadata is not None:
            metadata = json.loads(args.metadata.read_text())
            if metadata.get('version') != 1 or not metadata.get('packages') or metadata.get('resolve') is None:
                raise ValueError('Incomplete locked dependency metadata')
            check_lock(metadata['packages'])
        print('First-party declarations follow main; locked crate revisions are unique')
