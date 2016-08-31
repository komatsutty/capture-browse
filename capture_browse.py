#!/usr/bin/env python
import sys
import os.path
import logging
import signal
import argparse
import base64
import pyscreenshot
from xvfbwrapper import Xvfb
from selenium import webdriver
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException, NoAlertPresentException

class CapturePage(object):

    def __init__(self, width, height, colordepth):
        self.width = width
        self.height = height
        self.xvfb = Xvfb(width=width, height=height, colordepth=colordepth)
        self.xvfb.start()
        self.fp = webdriver.FirefoxProfile()
        self.fp.accept_untrusted_certs = True
        self.fp.set_preference('intl.accept_languages', 'ja-JP, ja')
        self.fp.set_preference('browser.cache.disk.enable', False)
        self.fp.set_preference('browser.cache.disk_cache_ssl', False)
        self.fp.set_preference('browser.cache.memory.enable', False)
        self.fp.set_preference('browser.cache.offline.enable', False)
        self.fp.set_preference('browser.safebrowsing.enabled', False)
        self.fp.set_preference('browser.safebrowsing.malware.enabled', False)
        self.fp.set_preference('browser.safebrowsing.downloads.enabled', False)
        self.fp.set_preference('services.sync.prefs.sync.browser.safebrowsing.enabled', False)
        self.fp.set_preference('services.sync.prefs.sync.browser.safebrowsing.malware.enabled', False)
        self.fp.set_preference('browser.safebrowsing.provider.mozilla.gethashURL', '')
        self.fp.set_preference('browser.safebrowsing.provider.mozilla.updateURL', '')
        self.fp.set_preference('browser.search.geoip.url', '')
        self.fp.set_preference('geo.enabled', False)
        self.fp.set_preference('app.update.enabled', False)
        self.fp.set_preference('browser.search.update', False)
        self.fp.set_preference('network.http.use-cache', False)
        self.fp.set_preference('network.http.pipelining', True)
        self.fp.set_preference('network.cookie.enableForCurrentSessionOnly', True)
        self.fp.set_preference('browser.chrome.favicons', False)
        self.fp.set_preference('browser.chrome.toolbar_tips', False)
        self.fp.set_preference('browser.shell.checkDefaultBrowser', False)
        self.fp.set_preference('accessibility.blockautorefresh', True)
        self.fp.set_preference('security.tls.unrestricted_rc4_fallback', True)
        self.fp.set_preference('security.tls.version.max', 3)
        self.fp.set_preference('security.tls.version.min', 0)
        self.fp.update_preferences()

    def proxy(self, proxy, proxy_port):
        self.fp.set_preference('network.proxy.type', 1)
        self.fp.set_preference('network.proxy.http', proxy)
        self.fp.set_preference('network.proxy.http_port', proxy_port)
        self.fp.set_preference('network.proxy.ssl', proxy)
        self.fp.set_preference('network.proxy.ssl_port', proxy_port)
        self.fp.update_preferences()

    def capture_page(self, page, file_name, page_timeout):
        self.browser = webdriver.Firefox(firefox_profile=self.fp)
        self.browser.delete_all_cookies()
        self.browser.set_window_size(self.width, self.height)
        self.browser.set_page_load_timeout(page_timeout)
        try:
            self.browser.get(page)
        except TimeoutException as err:
            logging.info('maybe this page did not load completely')
            logging.debug(type(err))
            pass
        try:
            WebDriverWait(self.browser, 5).until(EC.alert_is_present())
            (root, ext) = os.path.splitext(file_name)
            suffix = '(prompt)' + ext
            pyscreenshot.grab()
            pyscreenshot.grab_to_file(root + suffix)
            Alert(self.browser).dismiss()
        except NoAlertPresentException as err:
            logging.debug(type(err))
            pass
        except TimeoutException:
            pass
        pyscreenshot.grab()
        pyscreenshot.grab_to_file(file_name)
        self.browser.close()

    def quit(self):
        self.browser.quit()
        self.xvfb.stop()

def logo():
    message = b'''\
    ICAgICAgICAgICAgICAgICBfICAgICAgICAgICAgICAgICAgICBfICAgICAgICAg
    ICAgICAgICAgICAgICAgICAgICAgICAKICBfX18gX18gXyBfIF9fIHwgfF8gXyAg
    IF8gXyBfXyBfX18gIHwgfF9fICBfIF9fIF9fX19fICAgICAgX19fX18gIF9fXyAK
    IC8gX18vIF9gIHwgJ18gXHwgX198IHwgfCB8ICdfXy8gXyBcIHwgJ18gXHwgJ19f
    LyBfIFwgXCAvXCAvIC8gX198LyBfIFwKfCAoX3wgKF98IHwgfF8pIHwgfF98IHxf
    fCB8IHwgfCAgX18vIHwgfF8pIHwgfCB8IChfKSBcIFYgIFYgL1xfXyBcICBfXy8K
    IFxfX19cX18sX3wgLl9fLyBcX198XF9fLF98X3wgIFxfX198IHxfLl9fL3xffCAg
    XF9fXy8gXF8vXF8vIHxfX18vXF9fX3wKICAgICAgICAgIHxffCAgICAgICAgICAg
    ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAK\
    '''
    print(base64.b64decode(message).decode('utf-8'))

if __name__ == '__main__':
    def handler(num, frame):
        capture.quit()

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    parse = argparse.ArgumentParser()
    parse.add_argument('--host', type=str, help='target FQDN or IP address', required=True)
    parse.add_argument('--port', type=str, default='80', help='target port number')
    parse.add_argument('--scheme', type=str, default='http', help='scheme (http or https)')
    parse.add_argument('--path', type=str, default='/', help='path string')
    parse.add_argument('--query', type=str, help='query string')
    parse.add_argument('--fragment', type=str, help='fragment string')
    parse.add_argument('--filename', type=str, default='screenshot.png', help='filename for screenshot')
    parse.add_argument('--proxy', type=str, help='proxy address')
    parse.add_argument('--proxyport', type=int, help='proxy port')
    parse.add_argument('--timeout', type=int, default='10', help='duration')
    parse.add_argument('--width', type=str, default='1280', help='screen width')
    parse.add_argument('--height', type=str, default='720', help='screen height')
    parse.add_argument('--colordepth', type=str, default='16', help='screen color depth')
    parse.add_argument('--logo', action='store_true')
    parse.add_argument('--debug', action='store_true')
    args = parse.parse_args()

    if args.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(stream=sys.stderr, level=level)

    if args.logo:
        logo()
    uri = args.scheme + "://" + args.host + ":" + args.port + args.path
    if not args.query is None:
        uri = uri + '?' + args.query
    if not args.fragment is None:
        uri = uri + "#" + args.fragment
    file_name = args.filename
    width = args.width
    height = args.height
    color_depth = args.colordepth
    proxy = args.proxy
    proxy_port = args.proxyport
    page_timeout = args.timeout

    logging.info(uri)

    capture = CapturePage(width, height, color_depth)
    if not proxy is None:
        if not proxy_port is None:
            capture.proxy(proxy, proxy_port)
    capture.capture_page(uri, file_name, page_timeout)
    capture.quit()
