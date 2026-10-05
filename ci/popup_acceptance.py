"""Actual original frame + no-opener popup; no credential/secret JS fixture."""
from pathlib import Path
from urllib.parse import urlsplit

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait


def stage_popup(site):
    for filename in ['popup.html', 'popup-frame.html']:
        (site / filename).write_bytes((Path(__file__).parent / filename).read_bytes())
    (site / 'popup-member.html').write_text('''<!doctype html><html lang="en"><title>Member acceptance</title>
      <iframe title="Account security" sandbox="allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
        allow="publickey-credentials-get 'none'; publickey-credentials-create 'none'"></iframe>
      <button type="button" id="linked">Open linked refusal</button>
      <script>
        const vault = location.origin.replace('://alpha.localhost', '://vault.alpha.localhost');
        document.querySelector('iframe').src = vault + '/popup-frame.html';
        document.querySelector('button').onclick = () => window.open(vault + '/popup.html', '_blank');
      </script></html>''')


def run_popup(driver, page):
    # *.localhost is Chromium's reserved local name, no external DNS/proxy change.
    # alpha.localhost and vault.alpha.localhost exercise distinct origins on the
    # same schemeful site, required by BroadcastChannel's storage partition.
    member = f'https://alpha.localhost:{urlsplit(page).port}/popup-member.html'
    wait = WebDriverWait(driver, 40)
    driver.get(member)
    member_handle = driver.current_window_handle
    driver.switch_to.frame(driver.find_element(By.TAG_NAME, 'iframe'))
    wait.until(lambda d: d.find_element(By.ID, 'open').is_enabled())
    driver.find_element(By.ID, 'open').click()  # real vault-frame activation
    driver.switch_to.default_content()
    wait.until(lambda d: len(d.window_handles) == 2)
    popup = next(handle for handle in driver.window_handles if handle != member_handle)
    driver.switch_to.window(popup)
    wait.until(lambda d: d.execute_script('return document.body.dataset.state') == 'ready')
    if not driver.execute_script("return opener === null && location.hash === '' && isSecureContext"):
        raise RuntimeError('popup did not consume its isolated launch')
    driver.execute_cdp_cmd('WebAuthn.enable', {})
    driver.execute_cdp_cmd('WebAuthn.addVirtualAuthenticator', {'options': {
        'protocol': 'ctap2', 'ctap2Version': 'ctap2_1', 'transport': 'internal',
        'hasResidentKey': True, 'hasUserVerification': True, 'isUserVerified': True,
        'automaticPresenceSimulation': True, 'hasPrf': True,
    }})
    driver.find_element(By.ID, 'continue').click()  # independent popup activation
    wait.until(lambda d: d.execute_script('return document.body.dataset.state') == 'handed-over')
    driver.close()
    driver.switch_to.window(member_handle)
    driver.switch_to.frame(driver.find_element(By.TAG_NAME, 'iframe'))
    wait.until(lambda d: d.execute_script('return document.body.dataset.state') == 'received')
    driver.switch_to.default_content()
    driver.find_element(By.ID, 'linked').click()
    wait.until(lambda d: len(d.window_handles) == 2)
    driver.switch_to.window(next(handle for handle in driver.window_handles if handle != member_handle))
    wait.until(lambda d: d.execute_script('return document.body.dataset.state') == 'opener-refused')
    driver.close()
    driver.switch_to.window(member_handle)
    # Closing a real no-opener popup before Continue must cancel the frame owner.
    driver.get(member)
    driver.switch_to.frame(driver.find_element(By.TAG_NAME, 'iframe'))
    wait.until(lambda d: d.find_element(By.ID, 'open').is_enabled())
    driver.find_element(By.ID, 'open').click()
    driver.switch_to.default_content()
    wait.until(lambda d: len(d.window_handles) == 2)
    driver.switch_to.window(next(handle for handle in driver.window_handles if handle != member_handle))
    wait.until(lambda d: d.execute_script('return document.body.dataset.state') == 'ready')
    driver.close()
    driver.switch_to.window(member_handle)
    driver.switch_to.frame(driver.find_element(By.TAG_NAME, 'iframe'))
    wait.until(lambda d: d.execute_script('return document.body.dataset.state') == 'refused')
    driver.switch_to.default_content()
    return dict(sealed_handover=True, real_frame_and_popup_clicks=True,
                no_opener=True, linked_popup_refused=True, early_close_refused=True,
                same_site_distinct_origins=True)
