import sys
import os
import random
import time
import socket
import ssl
import math
import base64
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from urllib.request import Request, urlopen
from html.parser import HTMLParser
from colorama import init, Fore, Back, Style

ASCII_SECURITY_ART = [
    r"""
                          ____
                         / ___|  ___  _ __   ___  ___
                         \___ \ / _ \| '_ \ / _ \/ __|
                          ___) | (_) | | | |  __/\__ \
                         |____/ \___/|_| |_|\___||___/
    """,
    r"""
                                    _______
                                   / _____ \
                                  | |  ___  |
                                  | | |__ | |
                                  | |___| | |
                                   \_______/
    """,
    r"""
                                     ______
                                    / ____ \
                                   | | __ | |
                                   | ||__|| |
                                   | |____| |
                                    \______/
    """,
    r"""
                                     _________
                                    /\_____  \
                                   / /\____\  \
                                  / / /\___/\  \
                                  \/_/ /__/\\/__/
    """,
    r"""
                                     .----.
                                    /  .  \
                                   |  / \  |
                                   |  \_/  |
                                    \_____/
    """,
    r"""
                                    ____
                                   / __ \
                                  | |  | |  ___  ___  ___
                                  | |  | | / _ \/ __|/ _ \
                                  | |__| ||  __/\__ \  __/
                                   \____/  \___||___/\___|
    """,
    r"""
                                    .--------.
                                    |  LOCK  |
                                    |   __   |
                                    |  |__|  |
                                   '--------'
    """,
    r"""
                                     ______
                                    / ____ \
                                   | | SH | |
                                   | | IE | |
                                   | | LD | |
                                    \______/
    """,
    r"""
                                     .------.
                                    /  ____ \
                                   |  / __ \ |
                                   | | |  | ||
                                   | | |__| ||
                                    \_\____/_/
    """,
    r"""
                                     _____
                                    /  _  \
                                   |  /_\  |
                                   |  \_/  |
                                   \_____/
    """,
    r"""
                                     .-""-.
                                    / .-. \
                                   | |   | |
                                   | |   | |
                                    \ `-` /
                                     `---`
    """,
    r"""
                                     _______
                                    / ____  \
                                   | |    | |
                                   | |____| |
                                   |  ____  |
                                    \______/
    """,
    r"""
                                     .------.
                                    /  NET  \
                                   |  MAP   |
                                    \______/
    """,
    r"""
                                     .------.
                                    /  IDS  \
                                   | IPS/WAF|
                                    \______/
    """,
    r"""
                                     .------.
                                    /  KEY  \
                                   |  CTRL  |
                                    \______/
    """,
    r"""
                                    .------.
                                    /  TOR  \
                                   |  MASK  |
                                    \______/
    """,
    r"""
                                     .------.
                                    /  EYE  \
                                   | WATCH  |
                                    \______/
    """,
    r"""
                                     .------.
                                    /  BUG  \
                                   |  HUNT  |
                                    \______/
    """,
    r"""
                                     .------.
                                    /  CERT \
                                   |  TLS   |
                                    \______/
    """,
    r"""
                                  .-~~-.--.
                                 :         :
                                 .~ ~ ~ ~ ~.
                                (           )
                                 `-._______.-'
    """,
    r"""
                                   .-.
                                  (   )
                                   '-'
    """,
    r"""
                                 .-~~~-.
                                /       \\
                               |         |
                                \\       /
                                 '-~~~-'
    """,
    r"""
                                  .-.
                                 (   )
                                  '-'
                                   |
                                   |
    """,
    r"""
                                 .-~~~-.
                                /       \\
                               |  O   O  |
                                \\  ^^^  /
                                 '-~~~-'
    """,
    r"""
                                   .-.
                                  (   )
                                   '-'
                                    |
                                    |
                                   / \\
    """,
    r"""
                                 .-~~~-.
                                /       \\
                               |  >   <  |
                                \\  ^^^  /
                                 '-~~~-'
    """,
    r"""
                                  .-.
                                 (   )
                                  '-'
                                   |
                                   |
                                  /|\\
    """,
    r"""
                                 .-~~~-.
                                /       \\
                               |  ^   ^  |
                                \\  ---  /
                                 '-~~~-'
    """,
    """
                                   .-.
                                  (   )
                                   '-'
                                    |
                                    |
                                   / \\
                                  /   \\
    """,
    r"""
                                 .-~~~-.
                                /       \\
                               |  *   *  |
                                \\  ooo  /
                                 '-~~~-'
    """,
    r"""
                                  .-.
                                 (   )
                                  '-'
                                   |
                                   |
                                  /|\\
                                 / | \\
    """,
    r"""
                                 .-~~~-.
                                /       \\
                               |  @   @  |
                                \\  ---  /
                                 '-~~~-'
    """,
    r"""
                                   .-.
                                  (   )
                                   '-'
                                    |
                                    |
                                   / \\
                                  /   \\
                                 /     \\
    """,
    r"""
                                 .-~~~-.
                                /       \\
                               |  $   $  |
                                \\  $$$  /
                                 '-~~~-'
    """
]

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 500, 514, 515, 587, 631, 636, 873, 902, 990, 993, 995, 1025, 1433, 1521, 1723, 2049, 2077, 2078, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375, 2376, 3000, 3050, 3268, 3306, 3389, 3535, 3632, 3690, 4369, 4444, 4500, 5000, 5432, 5555, 5601, 5632, 5672, 5900, 5984, 6000, 6001, 6002, 6379, 6443, 6667, 7001, 7002, 7077, 7199, 7443, 7474, 7510, 7547, 8000, 8008, 8009, 8080, 8081, 8088, 8090, 8161, 8181, 8200, 8300, 8333, 8443, 8530, 8531, 8600, 8686, 8888, 9000, 9001, 9042, 9092, 9200, 9300, 9418, 9443, 9999, 10000, 11211, 27017
]

COLOR_CODES = [str(n) for n in [
    1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15, 27, 33, 39, 45, 51, 82, 196
]]

def color_text(text, code=None):
    if code is None:
        code = random.choice(COLOR_CODES)
    return f"\x1b[38;5;{code}m{text}\x1b[0m"

print(Fore.RED + Style.BRIGHT + "\n" + "="*100)
def print_big_banner():
    banner = [
        "████████╗███████╗ █████╗ ███╗   ███╗    ██████╗  █████╗ ██████╗ ██╗  ██╗    ██████╗     ██████╗",
        "╚══██╔══╝██╔════╝██╔══██╗████╗ ████║    ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ╚════██╗   ██╔═══██╗",
        "   ██║   █████╗  ███████║██╔████╔██║    ██║  ██║███████║██████╔╝█████╔╝      █████╔╝   ██║   ██║ ",
        "   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║    ██║  ██║██╔══██║██╔══██╗██╔═██╗     ██╔═══╝    ██║   ██║ ",
        "   ██║   ███████╗██║  ██║██║ ╚═╝ ██║    ██████╔╝██║  ██║██║  ██║██║  ██╗    ███████╗██╗╚██████╔╝",
        "   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝╚═╝ ╚═════╝",
    ]
    code = random.choice(COLOR_CODES)
    for line in banner:
        print(color_text(line, code))

def print_small_banner():
    print(Fore.GREEN + Style.BRIGHT + """
                   ====================================================
                         <<---  D A R K  T O O L  K I T S  --->>
                                 Create By: Team Dark 2.O
                   ====================================================
""")

def print_random_ascii_security_art():
    art = random.choice(ASCII_SECURITY_ART)
    code = random.choice(COLOR_CODES)
    print(color_text(art, code))

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'form':
            self.current = {'inputs': [], 'attrs': dict(attrs)}
            self.forms.append(self.current)
        elif tag.lower() == 'input' and self.current is not None:
            self.current['inputs'].append(dict(attrs))
        elif tag.lower() == 'textarea' and self.current is not None:
            self.current['inputs'].append({'name': dict(attrs).get('name', '')})

    def handle_endtag(self, tag):
        if tag.lower() == 'form':
            self.current = None

def safe_open(url, timeout=10):
    req = Request(url, headers={'User-Agent': 'TeamDark2O-Scanner'})
    try:
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            headers = dict(resp.info())
            code = resp.getcode()
            final_url = resp.geturl()
            return code, headers, data, final_url
    except Exception as e:
        return None, {}, b"", url
def normalize_url(u):
    u = u.strip()
    p = urlparse(u)
    if not p.scheme:
        if '://' not in u:
            if '/' in u or '?' in u:
                u = 'http://' + u
            else:
                u = 'http://' + u + '/'
        p = urlparse(u)
    if not p.netloc and p.path:
        u = 'http://' + p.path
        p = urlparse(u)
    return urlunparse((p.scheme or 'http', p.netloc, p.path or '/', p.params, p.query, p.fragment))

def build_url_with_params(base, params):
    parsed = urlparse(base)
    qs = parse_qs(parsed.query)
    for k, v in params.items():
        qs[k] = [v]
    new_query = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

def scan_xss(url):
    payload = '"<script>alert(1)</script>'
    test_url = build_url_with_params(url, {'xss': payload})
    code, headers, data, final = safe_open(test_url)
    if code and payload in data.decode(errors='ignore'):
        return True, 'Reflected payload detected'
    return False, 'No reflection detected'

def scan_csrf(url):
    code, headers, data, final = safe_open(url)
    parser = FormParser()
    parser.feed(data.decode(errors='ignore'))
    forms = parser.forms
    suspicious = []
    for f in forms:
        names = [inp.get('name', '') for inp in f['inputs'] if isinstance(inp, dict)]
        tokens = [n for n in names if n and ('csrf' in n.lower() or 'token' in n.lower())]
        if not tokens:
            suspicious.append(f)
    if suspicious:
        return True, f"{len(suspicious)} form(s) without CSRF token"
    return False, 'Forms appear to include CSRF tokens or none found'

def scan_traversal(url):
    test = '../../etc/passwd'
    test_url = build_url_with_params(url, {'file': test})
    code, headers, data, final = safe_open(test_url)
    text = data.decode(errors='ignore')
    if 'root:x:' in text or 'daemon:x:' in text:
        return True, 'Likely path traversal'
    return False, 'No traversal indications'

def scan_cmd_injection(url):
    marker = 'TDARK2O_INJ'
    payload = f";echo {marker}"
    test_url = build_url_with_params(url, {'cmd': payload})
    code, headers, data, final = safe_open(test_url)
    if code and marker in data.decode(errors='ignore'):
        return True, 'Command execution marker echoed'
    return False, 'No command execution marker found'

def scan_buffer_overflow(url):
    long_str = 'A' * 10000
    test_url = build_url_with_params(url, {'q': long_str})
    code, headers, data, final = safe_open(test_url)
    if code and code >= 500:
        return True, f"Server error {code} under oversized input"
    return False, 'No error under oversized input'

def scan_idor(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return False, 'No identifiable object references'
    for k, v in qs.items():
        try:
            val = int(v[0])
            alt_url = build_url_with_params(url, {k: str(val + 1)})
            code, headers, data, final = safe_open(alt_url)
            if code and code == 200 and alt_url != url:
                return True, f"Object reference {k} appears accessible"
        except Exception:
            continue
    return False, 'No IDOR indicators'

def scan_broken_auth(url):
    code, headers, data, final = safe_open(url)
    cookies = headers.get('Set-Cookie', '')
    if cookies:
        flags = cookies.lower()
        issues = []
        if 'httponly' not in flags:
            issues.append('Missing HttpOnly')
        if 'secure' not in flags and urlparse(url).scheme == 'https':
            issues.append('Missing Secure')
        if 'samesite' not in flags:
            issues.append('Missing SameSite')
        if issues:
            return True, ', '.join(issues)
    return False, 'No cookie flag issues observed'

def scan_sensitive_data(url):
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        return True, 'Uses plaintext HTTP'
    code, headers, data, final = safe_open(url)
    server = headers.get('Server')
    powered = headers.get('X-Powered-By')
    exposures = []
    if server:
        exposures.append(f"Server header: {server}")
    if powered:
        exposures.append(f"X-Powered-By: {powered}")
    if exposures:
        return True, '; '.join(exposures)
    return False, 'No obvious header exposures'

def scan_xxe(url):
    code, headers, data, final = safe_open(url)
    ct = headers.get('Content-Type', '')
    if 'xml' in ct.lower():
        return True, 'XML content detected; manual XXE tests recommended'
    return False, 'No XML endpoints detected'

def run_vulnerability_scan(url):
    checks = {
        'Cross-Site Scripting (XSS)': scan_xss,
        'Cross-Site Request Forgery (CSRF)': scan_csrf,
        'Directory Traversal': scan_traversal,
        'Command Injection': scan_cmd_injection,
        'Buffer Overflow': scan_buffer_overflow,
        'Insecure Direct Object References': scan_idor,
        'Broken Authentication': scan_broken_auth,
        'Sensitive Data Exposure': scan_sensitive_data,
        'XML External Entity (XXE)': scan_xxe,
    }
    results = {}
    for name, fn in checks.items():
        status, detail = fn(url)
        results[name] = {'vulnerable': status, 'detail': detail}
    return results

def save_vuln_report(url, results):
    os.makedirs('reports', exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join('reports', f'vuln_report_{ts}.txt')
    lines = []
    lines.append(f'Target: {url}')
    lines.append(f'Timestamp: {ts}')
    lines.append('Summary:')
    for k, v in results.items():
        lines.append(f'- {k}: {"FOUND" if v["vulnerable"] else "OK"} ({v["detail"]})')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    return path

def tcp_connect(host, port, timeout=0.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def scan_ports(host, ports, timeout=0.5, workers=200):
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(tcp_connect, host, p, timeout): p for p in ports}
        for fut in as_completed(futs):
            p = futs[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass
    return sorted(open_ports)

def save_port_report(host, mode, open_ports):
    os.makedirs('reports', exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join('reports', f'port_report_{mode}_{ts}.txt')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f'Target: {host}\n')
        f.write(f'Mode: {mode}\n')
        f.write(f'Timestamp: {ts}\n')
        f.write('Open ports:\n')
        if open_ports:
            for p in open_ports:
                f.write(f'- {p}\n')
        else:
            f.write('None detected\n')
    return path

def password_strength(password):
    length = len(password)
    classes = 0
    if any(c.islower() for c in password):
        classes += 1
    if any(c.isupper() for c in password):
        classes += 1
    if any(c.isdigit() for c in password):
        classes += 1
    if any(c in "!@#$%^&*()-_=+[]{};:'\",.<>/?|`~" for c in password):
        classes += 1
    pool = {1: 26, 2: 52, 3: 62, 4: 94}.get(classes, 10)
    guesses = pool ** length
    rate = 1e9
    seconds = guesses / rate
    if length < 8 or classes < 3:
        level = 'Week'
    elif length < 12 or classes < 4:
        level = 'Medium'
    else:
        level = 'Strong'
    return level, seconds

def suggest_password():
    import secrets
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>/?|'
    return ''.join(secrets.choice(chars) for _ in range(20))

def format_duration(seconds):
    if seconds < 1:
        return 'less than 1 second'
    units = [
        ('year', 31557600),
        ('day', 86400),
        ('hour', 3600),
        ('minute', 60),
        ('second', 1),
    ]
    parts = []
    for name, size in units:
        if seconds >= size:
            count = int(seconds // size)
            seconds -= count * size
            parts.append(f"{count} {name}{'' if count == 1 else 's'}")
    return ', '.join(parts)

def do_base64_encode_text(text):
    return base64.b64encode(text.encode('utf-8')).decode('ascii')

def do_base64_decode_text(text):
    try:
        return base64.b64decode(text.encode('ascii')).decode('utf-8', errors='ignore')
    except Exception:
        return ''

def do_base64_encode_file(path):
    with open(path, 'rb') as f:
        return base64.b64encode(f.read())

def do_base64_decode_file(path, out_path):
    with open(path, 'rb') as f:
        data = f.read()
    decoded = base64.b64decode(data)
    with open(out_path, 'wb') as f:
        f.write(decoded)

def generate_help():
    lines = []
    lines.append('Main Menu:')
    lines.append('1. Vulnerability Scanning')
    lines.append('   - Tests: XSS, CSRF, Directory Traversal, Command Injection, Buffer Overflow, IDOR, Broken Authentication, Sensitive Data Exposure, XXE')
    lines.append('   - Report is saved to reports/')
    lines.append('2. Password Tools')
    lines.append('   - Check strength and crack time')
    lines.append('   - Generate strong password')
    lines.append('3. Base64 Tools')
    lines.append('   - Encode/Decode text and files')
    lines.append('4. Session Report')
    lines.append('   - Summarize last vulnerability and port scan outputs')
    lines.append('5. Help')
    lines.append('0. Exit')
    return '\n'.join(lines)

SESSION = {
    'last_vuln_report': None,
    'last_port_report': None,
}

def menu_vulnerability():
    print('Enter target URL (e.g., https://example.com):')
    url = input('> ').strip()
    if not url:
        return
    url = normalize_url(url)
    print(color_text('Scanning...'))
    results = run_vulnerability_scan(url)
    path = save_vuln_report(url, results)
    SESSION['last_vuln_report'] = path
    print(color_text(f'Report saved: {path}'))

def menu_ports():
    print('Enter target host (domain or IP):')
    host = input('> ').strip()
    if not host:
        return
    print('Select mode: 1) Quick Scan  2) All Ports Scan')
    choice = input('> ').strip()
    if choice == '1':
        ports = COMMON_PORTS
        mode = 'quick'
    else:
        ports = list(range(1, 65536))
        mode = 'all'
    print(color_text('Port scanning...'))
    open_ports = scan_ports(host, ports)
    path = save_port_report(host, mode, open_ports)
    SESSION['last_port_report'] = path
    print(color_text(f'Report saved: {path}'))

def menu_password():
    print('1) Password Checker  2) Create Strong Password')
    choice = input('> ').strip()
    if choice == '1':
        print('Enter password to check:')
        pwd = input('> ')
        level, seconds = password_strength(pwd)
        print(f'Level: {level}')
        print(f'Estimated crack time: {format_duration(seconds)}')
        if level in ('Week', 'Medium'):
            print(f'Suggestion: {suggest_password()}')
    else:
        print(f'Generated: {suggest_password()}')

def menu_base64():
    print('1) Encode Text  2) Decode Text  3) Encode File  4) Decode File')
    choice = input('> ').strip()
    if choice == '1':
        print('Enter text:')
        text = input('> ')
        print(do_base64_encode_text(text))
    elif choice == '2':
        print('Enter base64 text:')
        text = input('> ')
        print(do_base64_decode_text(text))
    elif choice == '3':
        print('Enter file path:')
        path = input('> ').strip()
        if not os.path.isfile(path):
            print('File not found')
            return
        encoded = do_base64_encode_file(path)
        out = path + '.b64'
        with open(out, 'wb') as f:
            f.write(encoded)
        print(f'Encoded file saved: {out}')
    else:
        print('Enter base64 file path:')
        path = input('> ').strip()
        if not os.path.isfile(path):
            print('File not found')
            return
        out = path.rsplit('.', 1)[0] + '.decoded'
        try:
            do_base64_decode_file(path, out)
            print(f'Decoded file saved: {out}')
        except Exception:
            print('Decoding failed')

def menu_session_report():
    os.makedirs('reports', exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join('reports', f'session_{ts}.txt')
    lines = []
    lines.append('Session Report')
    lines.append(f'Timestamp: {ts}')
    lines.append(f'Vulnerability Report: {SESSION.get("last_vuln_report") or "None"}')
    lines.append(f'Port Report: {SESSION.get("last_port_report") or "None"}')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(color_text(f'Report saved: {path}'))


print(Fore.RED + Style.BRIGHT + "\n" + "="*100)
def main_menu():
    while True:
        os.system('')
        print_big_banner()
        print_small_banner()
        print_random_ascii_security_art()
        print(Fore.YELLOW + Style.BRIGHT + "\n" + "="*100)
        print(Fore.BLUE + "Main Menu:")
        print(Fore.YELLOW + "1. Vulnerability Scanning")
        print(Fore.YELLOW + "2. Password Tools")
        print(Fore.YELLOW + "3. Base64 Tools")
        print(Fore.YELLOW + "4. Generate Session Report")
        print(Fore.GREEN + "5. Help")
        print(Fore.RED + "0. Exit")
        print(Fore.GREEN + Style.BRIGHT + "\n" + "="*100)
        choice = input(Fore.GREEN + ">").strip()
        if choice == '1':
            print('1.1 Vulnerability Scanning  1.2 Port Scanning')
            sub = input('> ').strip()
            if sub == '1.1' or sub == '1':
                menu_vulnerability()
            else:
                menu_ports()
        elif choice == '2':
            menu_password()
        elif choice == '3':
            menu_base64()
        elif choice == '4':
            menu_session_report()
        elif choice == '5':
            print(generate_help())
            input('Press Enter to continue...')
        elif choice == '0':
            print(color_text('Goodbye'))
            break
        else:
            print('Invalid choice')
        time.sleep(0.5)

if __name__ == '__main__':
    try:
        main_menu()
    except KeyboardInterrupt:
        pass

