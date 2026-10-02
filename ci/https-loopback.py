#!/usr/bin/env python3
"""Actual HTTPS browser -> production loopback -> original Keyhole/libSQL test."""
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from selenium import webdriver
from selenium.webdriver.chrome.service import Service


def build(example, target=None):
    command = ['cargo', 'build', '--locked', '--all-features', '--example', example,
               '--message-format=json-render-diagnostics']
    if target:
        command += ['--target', target]
    completed = subprocess.run(command, stdout=subprocess.PIPE, text=True, check=True)
    artifacts = []
    for line in completed.stdout.splitlines():
        value = json.loads(line)
        if value.get('reason') == 'compiler-message':
            print(value['message'].get('rendered', ''), end='', flush=True)
        if value.get('reason') == 'compiler-artifact' and value['target']['name'] == example:
            if target:
                artifacts.extend(Path(p) for p in value['filenames'] if p.endswith('.wasm'))
            elif value.get('executable'):
                artifacts.append(Path(value['executable']))
    if len(artifacts) != 1:
        raise RuntimeError('one exact fixture build artifact required')
    return artifacts[0]


class QuietFiles(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        super().end_headers()


def main():
    artifacts = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
    native = build('loopback_native')
    wasm = build('loopback_page', 'wasm32-unknown-unknown')
    browser = os.environ.get('CHROME_BIN') or shutil.which('chromium')
    driver_path = os.environ.get('CHROMEDRIVER') or shutil.which('chromedriver')
    if not browser or not driver_path:
        raise RuntimeError('qualified browser tools are required')
    with tempfile.TemporaryDirectory(prefix='cpky-https-loopback-', dir='/tmp') as scratch:
        root = Path(scratch)
        site = root / 'site'
        site.mkdir()
        subprocess.run(['wasm-bindgen', str(wasm), '--target', 'web', '--out-dir', str(site)], check=True)
        (site / 'index.html').write_text('<!doctype html><title>Passkeys acceptance</title>')
        # Test-only maintained TLS certificate; destroyed with the private scratch.
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(QuietFiles, directory=str(site)))
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / 'cert.pem', root / 'key.pem')
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        page = f'https://localhost:{server.server_address[1]}/index.html'
        process = None
        driver = None
        try:
            options = webdriver.ChromeOptions()
            options.binary_location = browser
            options.add_argument('--headless=new')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.set_capability('acceptInsecureCerts', True)  # Only this generated local test certificate.
            driver = webdriver.Chrome(service=Service(driver_path), options=options)
            driver.set_page_load_timeout(120)
            driver.set_script_timeout(120)
            driver.execute_cdp_cmd('WebAuthn.enable', {})
            driver.execute_cdp_cmd('WebAuthn.addVirtualAuthenticator', {'options': {
                'protocol': 'ctap2', 'ctap2Version': 'ctap2_1', 'transport': 'internal',
                'hasResidentKey': True, 'hasUserVerification': True, 'isUserVerified': True,
                'automaticPresenceSimulation': True, 'hasPrf': True,
            }})
            process = subprocess.Popen([str(native), page, str(root)], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, umask=0o077)
            for phase in [1, 2]:
                until = time.monotonic() + 120
                launch = None
                while time.monotonic() < until:
                    if process.poll() is not None:
                        raise RuntimeError('native fixture exited before the browser ceremony')
                    file = root / 'launch.json'
                    if file.exists():
                        value = json.loads(file.read_text())
                        if value['phase'] == phase:
                            launch = value['url']
                            break
                    time.sleep(0.05)
                if launch is None:
                    raise RuntimeError('native ceremony launch deadline')
                # The capability remains in ephemeral private test memory. It is
                # never copied into a log, public receipt, HTTP query or API result.
                driver.get(launch)
                result = driver.execute_async_script('''
                    const done = arguments[0];
                    (async () => {
                        if (!window.isSecureContext) throw new Error('secure context required');
                        const api = await import('./loopback_page.js');
                        await api.default();
                        await api.complete();
                        done({completed: true, fragment_removed: window.location.hash === ''});
                    })().catch(() => done({completed: false}));
                ''')
                if result != {'completed': True, 'fragment_removed': True}:
                    raise RuntimeError('actual HTTPS-to-loopback ceremony refused')
            stdout, stderr = process.communicate(timeout=30)
            if process.returncode != 0:
                raise RuntimeError('original Keyhole verification refused')
            expected = dict(registration_verified=True, authentication_verified=True, same_prf=True)
            if json.loads(stdout) != expected:
                raise RuntimeError('incomplete native ceremony result')
            receipt = dict(status='passed', secure_context=True, fragment_removed=True,
                           backend='original Keyhole/libSQL', browser='actual Chromium WebAuthn test authenticator',
                           native_sha256=hashlib.sha256(native.read_bytes()).hexdigest(),
                           wasm_sha256=hashlib.sha256(wasm.read_bytes()).hexdigest(), **expected)
            (artifacts / 'https-loopback.json').write_text(json.dumps(receipt, indent=2) + '\n')
            print('Actual HTTPS registration/authentication -> numeric loopback -> Keyhole/libSQL PASS', flush=True)
        except Exception as error:
            # WebDriver exceptions may include the current URL fragment. Retain
            # only the coarse class; no launch capability can enter CI output.
            raise RuntimeError('HTTPS loopback acceptance failed: ' + type(error).__name__) from None
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if driver is not None:
                driver.quit()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    main()
