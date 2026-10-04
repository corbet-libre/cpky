"""Hostile HTTP transcripts for the original Wasm callback, never an authenticator."""
import gzip
import http.server
import secrets
import threading
from urllib.parse import urlencode, urlsplit


def run_refusals(driver, page):
    """Await each original completion and require refusal before a finish POST."""
    origin = urlsplit(page)
    origin = f'{origin.scheme}://{origin.netloc}'
    capability = secrets.token_urlsafe(32)
    encoded = gzip.compress(b'{}', mtime=0)
    # These are deliberately invalid peer responses, not valid server options.
    # Content-Length errors may be rejected by Fetch before the Wasm parser.
    cases = [
        ('refused-status', 403, b'{}', '2'),
        ('redirect', 302, b'', '0'),
        ('missing-length', 200, b'{}', None),
        ('invalid-length', 200, b'{}', 'invalid'),
        ('over-limit', 200, b' ' * 262145, '262145'),
        ('short-body', 200, b'{', '2'),
        ('encoded-length-mismatch', 200, encoded, str(len(encoded))),
        ('invalid-json', 200, b'{', '1'),
        ('invalid-ceremony', 200, b'{"kind":"Authentication","options":{}}', None),
    ]
    # The final case has an exact valid transport length, so only the original
    # ceremony/options parser can refuse it.
    name, status, body, _ = cases[-1]
    cases[-1] = (name, status, body, str(len(body)))
    observed = []
    preflights = []

    class BoundedPeer(http.server.HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            # Bound both idle preconnects and partial headers/bodies. A request
            # handler cannot prevent shutdown indefinitely during cleanup.
            connection.settimeout(5)
            return connection, address

    class HostilePeer(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def cors(self):
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'x-cpky-capability, content-type')
            self.send_header('Access-Control-Allow-Private-Network', 'true')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')

        def do_OPTIONS(self):
            preflights.append('OPTIONS')
            self.send_response(204)
            self.cors()
            self.end_headers()

        def do_GET(self):
            valid = (self.path == '/request'
                     and self.headers.get('Origin') == origin
                     and self.headers.get('x-cpky-capability') == capability)
            observed.append(('GET', valid))
            name, status, body, length = self.server.transcript
            self.send_response(status if valid else 403)
            self.cors()
            if length is not None:
                self.send_header('Content-Length', length)
            if name == 'redirect':
                self.send_header('Location', '/request')
            if name == 'encoded-length-mismatch':
                # Fetch exposes decoded bytes, while this is the correct wire
                # length. The original callback must refuse the discrepancy.
                self.send_header('Content-Encoding', 'gzip')
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                # A browser may stop reading as soon as the refusal is known.
                pass

        def do_POST(self):
            observed.append(('POST', False))
            self.send_response(405)
            self.cors()
            self.send_header('Content-Length', '0')
            self.end_headers()

    peer = BoundedPeer(('127.0.0.1', 0), HostilePeer)
    thread = threading.Thread(target=peer.serve_forever, daemon=True)
    thread.start()
    receipts = []
    try:
        endpoint = f'http://127.0.0.1:{peer.server_address[1]}/finish'
        fragment = urlencode({'cpky-v1': endpoint, 'cap': capability})
        peer.transcript = cases[0]
        navigation = driver.execute_async_script('''
            const [fragment, done] = arguments;
            (async () => {
                history.replaceState(null, '', '#' + fragment);
                const target = new URL(location.href);
                target.hash = '';
                const api = await import('./loopback_page.js');
                let events = 0, cancelled = false, trusted = false, unavailable = false;
                const cancel = event => {
                    if (event.navigationType === 'replace' && event.destination.sameDocument
                            && event.destination.url === target.href) {
                        events++;
                        trusted = event.isTrusted && event.cancelable;
                        event.preventDefault();
                        cancelled = event.defaultPrevented;
                    }
                };
                navigation.addEventListener('navigate', cancel);
                let retained;
                try {
                    try { await api.navigation_refusal(); unavailable = true; }
                    catch (_) { unavailable = false; }
                    retained = location.hash === '#' + fragment;
                } finally {
                    navigation.removeEventListener('navigate', cancel);
                    history.replaceState(null, '', target.href);
                }
                done({unavailable, retained_fragment: retained, cancelled, trusted,
                      events, cleanup_complete: location.hash === ''});
            })().catch(() => done({fixture_failed: true}));
        ''', fragment)
        expected_navigation = dict(unavailable=True, retained_fragment=True, cancelled=True,
                                   trusted=True, events=1, cleanup_complete=True)
        # Awaiting the original callback is the completion boundary. A canceled
        # fragment removal must issue no preflight, request or finish at all.
        if navigation != expected_navigation or observed or preflights:
            raise RuntimeError('canceled fragment removal did not refuse before I/O')
        navigation.update(options=0, request_gets=0, finish_posts=0)
        for transcript in cases:
            print('Original callback refusal transcript: ' + transcript[0], flush=True)
            peer.transcript = transcript
            observed.clear()
            result = driver.execute_async_script('''
                const [fragment, done] = arguments;
                (async () => {
                    history.replaceState(null, '', '#' + fragment);
                    const api = await import('./loopback_page.js');
                    let refused = false;
                    try { await api.complete(); }
                    catch (error) { refused = error === 'ceremony refused'; }
                    done({refused, fragment_removed: location.hash === ''});
                })().catch(() => done({fixture_failed: true}));
            ''', fragment)
            # complete_loopback awaits every fetch and POST. Its returned
            # refusal is the synchronization point; no timing-based sleep can
            # falsely establish that a late finish was absent.
            if result != {'refused': True, 'fragment_removed': True} or observed != [('GET', True)]:
                raise RuntimeError('original callback did not refuse transcript: ' + transcript[0])
            receipts.append(dict(case=transcript[0], refused=True, request_gets=1, finish_posts=0))
        return receipts, navigation
    finally:
        peer.shutdown()
        peer.server_close()
        thread.join(timeout=5)
