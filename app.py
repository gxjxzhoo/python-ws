#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import json
import time
import signal
import platform
import threading
import urllib.request
import socket
import struct
import hashlib
import base64
import asyncio
import aiohttp
import logging
import ipaddress
import subprocess
import uuid as _uuid_mod
from urllib.parse import urlparse, quote
from aiohttp import web

try:
    import websocket as _ws_client  # pip install websocket-client ; 用于探针的实时WSS上报,缺失时会尝试自动安装
    _WS_AVAILABLE = True
except ImportError:
    _WS_AVAILABLE = False

# 环境变量
MAIN = ''
DOMAIN = ''
UUID = ''


def _env_int(key, default):
    try:
        return int(str(os.environ.get(key) or default).strip())
    except (TypeError, ValueError):
        return int(default)


UUID = os.environ.get('UUID', UUID)   # 节点UUID
DOMAIN = os.environ.get('DOMAIN', DOMAIN)                # 项目分配的域名或反代后的域名,不包含https://前缀,例如: domain.xxx.com
CFIP = os.environ.get('CFIP', 'cf.877774.xyz')         # CDN节点的优选ip或域名,留空则CDN节点直接连DOMAIN;仅在设置了DOMAIN时生效
CFPORT = _env_int('CFPORT', 443)                       # 优选端口
SUB_PATH = os.environ.get('SUB_PATH', 'sub')         # 节点订阅token
NAME = os.environ.get('NAME', MAIN)                    # 节点名称
WSPATH = os.environ.get('WSPATH', UUID[:8])          # 节点路径
PORT = _env_int('SERVER_PORT', 0) or _env_int('PORT', 3000)  # http和ws端口，默认自动优先获取容器分配的端口
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true' # 自动访问保活,默认关闭,true开启,false关闭,需同时填写DOMAIN变量
DEBUG = os.environ.get('DEBUG', '').lower() == 'true' # 保持默认,调试使用,true开启调试
SHOW_LOG = os.environ.get('SHOW_LOG', 'true').lower() not in ('false', 'disable', 'no')  # 是否显示日志,设为 false 关闭; DEBUG=true 时强制显示
CHAT_ID = os.environ.get('CHAT_ID', '8228961011')                # Telegram chat_id
BOT_TOKEN = os.environ.get('BOT_TOKEN', '8925427147:AAFlVkAUDQhYnaX2C5So5aU_ltNrCyHACu4')            # Telegram bot_token
DAEMON = os.environ.get('DAEMON', 'true').lower() not in ('false', '0', 'no', 'disable')  # 进程守护: 子进程意外退出后自动拉起, 默认开启
ENABLE_UDP = os.environ.get('ENABLE_UDP', 'true').lower() not in ('false', '0', 'no', 'disable')  # 是否允许 UDP 转发(VLESS/Trojan), 默认开启

# ---- 转发调优(一般无需修改) ----
BUF_SIZE = _env_int('BUF_SIZE', 65536)                 # TCP 转发单次读取字节数
CONNECT_TIMEOUT = _env_int('CONNECT_TIMEOUT', 10)      # 连接目标超时(秒)
DNS_CACHE_TTL = _env_int('DNS_CACHE_TTL', 300)         # DNS 缓存秒数
UDP_IDLE_TIMEOUT = _env_int('UDP_IDLE_TIMEOUT', 180)   # UDP 会话空闲多久关闭(秒)
WS_HEARTBEAT = _env_int('WS_HEARTBEAT', 30)            # WebSocket 心跳间隔(秒), 及时清理死连接

# ---- CF-Server-Monitor 上报 (纯 Python 实现, 不依赖官方 cf-probe 二进制) ----
# 官方 cf-probe 的 install 子命令必须依赖 systemd(root 或 systemd --user),
# bot 托管容器没有 systemd, 装不上, 所以这里直接读 /proc 自己拼 JSON 上报,
# 不下载任何二进制, 不需要 root。
PROBE_ID = os.environ.get('PROBE_ID', UUID)      # 探针 ID
PROBE_SECRET = os.environ.get('PROBE_SECRET', '585800')                            # 上报密钥
PROBE_URL = os.environ.get('PROBE_URL', 'https://cf-server-monitor.gxjx.eu.cc/update')  # Worker 上报地址
PROBE_INTERVAL = _env_int('PROBE_INTERVAL', 60)                                    # 上报间隔(秒)
PROBE_CT = os.environ.get('PROBE_CT', 'gd-ct-dualstack.ip.zstaticcdn.com')          # 电信测速节点 host[:port]
PROBE_CU = os.environ.get('PROBE_CU', 'gd-cu-dualstack.ip.zstaticcdn.com')          # 联通测速节点 host[:port]
PROBE_CM = os.environ.get('PROBE_CM', 'gd-cm-dualstack.ip.zstaticcdn.com')          # 移动测速节点 host[:port]
PROBE_PING_COUNT = _env_int('PROBE_PING_COUNT', 2)                                 # 每次测速的 TCP 连接次数
PROBE_PING_TIMEOUT = float(os.environ.get('PROBE_PING_TIMEOUT', '1.0'))            # 单次连接超时(秒)
PROBE_IP_REFRESH_INTERVAL = _env_int('PROBE_IP_REFRESH_INTERVAL', 1800)            # 公网IP刷新间隔(秒), 不必每次上报都查
PROBE_WSS = os.environ.get('PROBE_WSS', 'true').lower() not in ('false', '0', 'no', 'disable')  # 是否尝试WSS实时上报(秒级刷新);建不了连接会自动退回POST轮询(60秒一次)
PROBE_PING_CACHE_TTL = _env_int('PROBE_PING_CACHE_TTL', 120)  # 三网 ping 缓存秒数

_probe_ping_cache = {
    'ts': 0,
    'ping_ct': None, 'loss_ct': None,
    'ping_cu': None, 'loss_cu': None,
    'ping_cm': None, 'loss_cm': None,
}

# 全局变量
CurrentDomain = DOMAIN
CurrentPort = 443
ActualPort = PORT   # 服务实际监听的端口(启动时自动确定,端口被占用会自动顺延)
PublicIP = ''       # 自动获取的公网IP(缓存)
Tls = 'tls'
ISP = ''
HTTP = None         # 全局复用的 aiohttp ClientSession(启动后创建)
RESTARTS = _env_int('_APP_WS_RESTARTS', 0)  # 守护进程重启次数, >0 时不重复推送 TG

# 启动时预计算(见 validate_config)
UUID_BYTES = b''
TROJAN_HASHES = set()
INDEX_HTML = None

# dns server (系统 DNS 解析失败时才会用 DoH 兜底)
DOH_SERVERS = [
    'https://dns.google/resolve',
    'https://cloudflare-dns.com/dns-query',
]
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
]

# 日志级别
if DEBUG:
    log_level = logging.DEBUG
elif SHOW_LOG:
    log_level = logging.INFO
else:
    log_level = logging.CRITICAL + 1  # 关闭所有日志
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 禁用访问,连接等日志
logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)
logging.getLogger('aiohttp.websocket').setLevel(logging.WARNING)
logging.getLogger('asyncio').setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)


def always_log(msg):
    # 不受 SHOW_LOG 控制的关键输出
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()


def validate_config():
    # 启动前检查关键变量, 配置错误直接给出明确提示(退出码 2, 守护进程不会反复重启)
    global UUID, UUID_BYTES, TROJAN_HASHES, WSPATH
    try:
        u = _uuid_mod.UUID(UUID.strip())
    except (ValueError, AttributeError):
        always_log(f'❌ UUID 无效或为空: {UUID!r}, 请设置正确的 UUID 环境变量')
        sys.exit(2)
    UUID = str(u)
    UUID_BYTES = u.bytes
    TROJAN_HASHES = {
        hashlib.sha224(UUID.encode()).hexdigest().encode(),
        hashlib.sha224(UUID.replace('-', '').encode()).hexdigest().encode(),
    }
    WSPATH = (WSPATH or '').strip().strip('/')
    if not WSPATH:
        WSPATH = UUID[:8]
    if WSPATH == SUB_PATH.strip('/'):
        always_log(f'❌ WSPATH 与 SUB_PATH 不能相同(当前都为 {WSPATH!r})')
        sys.exit(2)
    if not SUB_PATH.strip('/'):
        always_log('❌ SUB_PATH 不能为空')
        sys.exit(2)


def _raise_nofile_limit():
    # 提高文件描述符上限, 并发连接多时避免 Too many open files
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = hard if hard != resource.RLIM_INFINITY else 65535
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


def is_port_available(port, host='0.0.0.0'):
    # 加 SO_REUSEADDR: 守护重启后旧连接处于 TIME_WAIT 时也能判断为可用, 避免端口被误顺延
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def find_available_port(start_port, max_attempts=100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None


def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    host_lower = host.lower().rstrip('.')
    return any(host_lower == blocked or host_lower.endswith('.' + blocked)
               for blocked in BLOCKED_DOMAINS)


def _session():
    global HTTP
    if HTTP is None or HTTP.closed:
        HTTP = aiohttp.ClientSession(headers={'User-Agent': 'Mozilla/5.0'})
    return HTTP


async def get_isp():
    global ISP
    if ISP and ISP != 'Unknown':   # 已获取过就不再重复请求
        return
    t = aiohttp.ClientTimeout(total=3)
    try:
        async with _session().get('https://api.ip.sb/geoip', timeout=t) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                ISP = f"{data.get('country_code', '')}-{data.get('isp', '')}".replace(' ', '_')
                return
    except Exception:
        pass

    try:
        async with _session().get('http://ip-api.com/json', timeout=t) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                ISP = f"{data.get('countryCode', '')}-{data.get('org', '')}".replace(' ', '_')
                return
    except Exception:
        pass

    ISP = 'Unknown'


def _fmt_host(ip):
    # IPv6 地址在链接里需要加方括号
    return f'[{ip}]' if ':' in ip else ip


async def get_public_ip():
    # 自动获取服务器公网IP,成功后缓存,失败不缓存(下次再试)
    global PublicIP
    if PublicIP:
        return PublicIP
    sources = [
        'https://api-ipv4.ip.sb/ip',
        'https://api.ipify.org',
        'https://ipv4.icanhazip.com',
        'https://ifconfig.me/ip',
        'https://api6.ipify.org',
    ]
    t = aiohttp.ClientTimeout(total=5)
    for url in sources:
        try:
            async with _session().get(url, timeout=t) as resp:
                if resp.status == 200:
                    ip = (await resp.text()).strip()
                    if _looks_like_ip(ip):
                        PublicIP = ip
                        return ip
        except Exception:
            continue
    logger.error('Failed to get public IP')
    return ''


async def get_ip():
    global CurrentDomain, Tls, CurrentPort
    if not DOMAIN or DOMAIN == 'your-domain.com':
        ip = await get_public_ip()
        if ip:
            CurrentDomain = _fmt_host(ip)
            Tls = 'none'
            CurrentPort = ActualPort
        else:
            CurrentDomain = 'change-your-domain.com'
            Tls = 'tls'
            CurrentPort = 443
    else:
        CurrentDomain = DOMAIN
        Tls = 'tls'
        CurrentPort = 443

# =========================== DNS (系统解析 + 缓存 + DoH 兜底) ===========================
_dns_cache = {}   # host -> (expire_ts, [(family, ip), ...])


async def _doh_lookup(host):
    res = []
    t = aiohttp.ClientTimeout(total=5)
    for server in DOH_SERVERS:
        for qtype, fam in (('A', socket.AF_INET), ('AAAA', socket.AF_INET6)):
            try:
                url = f'{server}?name={quote(host)}&type={qtype}'
                async with _session().get(url, headers={'Accept': 'application/dns-json'}, timeout=t) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json(content_type=None)
                    for ans in data.get('Answer') or []:
                        ip = ans.get('data', '')
                        if ans.get('type') in (1, 28) and _looks_like_ip(ip):
                            res.append((fam, ip))
            except Exception:
                continue
        if res:
            break
    return res


async def resolve_addrs(host):
    # 返回 [(family, ip)], IPv4 优先(很多容器 IPv6 出站不通), 结果缓存 DNS_CACHE_TTL 秒
    try:
        ip = ipaddress.ip_address(host)
        return [(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, str(ip))]
    except ValueError:
        pass

    now = time.time()
    hit = _dns_cache.get(host)
    if hit and hit[0] > now:
        return hit[1]

    addrs = []
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), 5)
        for fam, _t, _p, _c, sa in infos:
            item = (fam, sa[0])
            if fam in (socket.AF_INET, socket.AF_INET6) and item not in addrs:
                addrs.append(item)
    except Exception:
        addrs = []
    if not addrs:
        addrs = await _doh_lookup(host)
    if not addrs:
        raise OSError(f'DNS resolve failed: {host}')

    addrs.sort(key=lambda a: 0 if a[0] == socket.AF_INET else 1)
    if len(_dns_cache) > 4096:
        _dns_cache.clear()
    _dns_cache[host] = (now + DNS_CACHE_TTL, addrs)
    return addrs


def _tune_sock(sock):
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass


async def open_target(host, port):
    # 依次尝试解析出的地址(最多4个), 单个超时 CONNECT_TIMEOUT 秒
    addrs = await resolve_addrs(host)
    last_err = None
    for _fam, ip in addrs[:4]:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, limit=BUF_SIZE * 2), CONNECT_TIMEOUT)
            _tune_sock(writer.get_extra_info('socket'))
            return reader, writer
        except Exception as e:
            last_err = e
    raise last_err or OSError(f'connect failed: {host}:{port}')

# =========================== 协议解析 ===========================


class _Short(Exception):
    pass


def _need(buf, off, n):
    if off + n > len(buf):
        raise _Short()


def _parse_addr(buf, off, t_v4, t_dom, t_v6):
    # 解析 [atyp][addr], 返回 (host, 新偏移); 数据不够抛 _Short, 非法抛 ValueError
    _need(buf, off, 1)
    atyp = buf[off]
    off += 1
    if atyp == t_v4:
        _need(buf, off, 4)
        return str(ipaddress.IPv4Address(bytes(buf[off:off + 4]))), off + 4
    if atyp == t_dom:
        _need(buf, off, 1)
        n = buf[off]
        off += 1
        _need(buf, off, n)
        host = bytes(buf[off:off + n]).decode('utf-8')
        if not host:
            raise ValueError('empty host')
        return host, off + n
    if atyp == t_v6:
        _need(buf, off, 16)
        return str(ipaddress.IPv6Address(bytes(buf[off:off + 16]))), off + 16
    raise ValueError(f'bad atyp {atyp}')


def parse_vless_header(buf):
    # 返回 (cmd, host, port, payload_offset); 不是 VLESS 返回 None
    if len(buf) < 18 or buf[0] != 0 or buf[1:17] != UUID_BYTES:
        return None
    off = 17
    _need(buf, off, 1)
    off += 1 + buf[off]            # 跳过 addons
    _need(buf, off, 1)
    cmd = buf[off]
    if cmd == 3:
        return cmd, '', 0, off + 1     # Mux/XUDP: 命令后没有目标地址, 直接是 Mux 帧
    _need(buf, off, 3)
    port = struct.unpack('!H', buf[off + 1:off + 3])[0]
    off += 3
    host, off = _parse_addr(buf, off, 1, 2, 3)
    return cmd, host, port, off


def parse_trojan_header(buf):
    # 返回 (cmd, host, port, payload_offset); 不是 Trojan 返回 None
    if len(buf) < 58 or bytes(buf[:56]) not in TROJAN_HASHES:
        return None
    off = 56
    if buf[off:off + 2] == b'\r\n':
        off += 2
    _need(buf, off, 1)
    cmd = buf[off]
    off += 1
    host, off = _parse_addr(buf, off, 1, 3, 4)
    _need(buf, off, 2)
    port = struct.unpack('!H', buf[off:off + 2])[0]
    off += 2
    if buf[off:off + 2] == b'\r\n':
        off += 2
    return cmd, host, port, off


def _pack_trojan_addr(ip, port):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        b = ip.encode()
        return bytes([3, len(b)]) + b + struct.pack('!H', port)
    if a.version == 4:
        return b'\x01' + a.packed + struct.pack('!H', port)
    if a.ipv4_mapped:
        return b'\x01' + a.ipv4_mapped.packed + struct.pack('!H', port)
    return b'\x04' + a.packed + struct.pack('!H', port)

# =========================== 转发 ===========================


async def _finish(tasks):
    # 任一方向结束就取消其余方向, 避免连接半挂
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    await asyncio.gather(*done, *pending, return_exceptions=True)


async def relay_tcp(ws, reader, writer):
    async def ws_to_tcp():
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.BINARY:
                writer.write(msg.data)
                if writer.transport.get_write_buffer_size() > BUF_SIZE:
                    await writer.drain()
            elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                break

    async def tcp_to_ws():
        while True:
            data = await reader.read(BUF_SIZE)
            if not data:
                break
            await ws.send_bytes(data)

    try:
        await _finish([asyncio.ensure_future(ws_to_tcp()), asyncio.ensure_future(tcp_to_ws())])
    finally:
        try:
            writer.close()
        except Exception:
            pass


class _UdpProto(asyncio.DatagramProtocol):
    def __init__(self, on_data):
        self.on_data = on_data

    def datagram_received(self, data, addr):
        self.on_data(data, addr)

    def error_received(self, exc):
        pass


class _UdpSession:
    # 公共部分: 接收队列 + 空闲超时
    def __init__(self):
        self.q = asyncio.Queue(maxsize=512)
        self.last = time.time()
        self.transports = []

    def on_data(self, data, addr):
        self.last = time.time()
        if not self.q.full():
            self.q.put_nowait((data, addr))

    async def idle_watch(self):
        while True:
            await asyncio.sleep(15)
            if time.time() - self.last > UDP_IDLE_TIMEOUT:
                return

    def close(self):
        for tr in self.transports:
            try:
                tr.close()
            except Exception:
                pass


async def relay_vless_udp(ws, host, port, rest):
    # VLESS UDP: 目标固定, 数据格式 [len:2][payload]
    fam, ip = (await resolve_addrs(host))[0]
    loop = asyncio.get_running_loop()
    sess = _UdpSession()
    tr, _ = await loop.create_datagram_endpoint(lambda: _UdpProto(sess.on_data), remote_addr=(ip, port), family=fam)
    sess.transports.append(tr)
    buf = bytearray(rest)

    def flush():
        while len(buf) >= 2:
            n = struct.unpack('!H', buf[:2])[0]
            if len(buf) < 2 + n:
                break
            tr.sendto(bytes(buf[2:2 + n]))
            del buf[:2 + n]
        sess.last = time.time()

    async def up():
        flush()
        async for msg in ws:
            if msg.type != aiohttp.WSMsgType.BINARY:
                break
            buf.extend(msg.data)
            flush()

    async def down():
        while True:
            data, _addr = await sess.q.get()
            await ws.send_bytes(struct.pack('!H', len(data)) + data)

    try:
        await _finish([asyncio.ensure_future(up()), asyncio.ensure_future(down()), asyncio.ensure_future(sess.idle_watch())])
    finally:
        sess.close()


async def relay_trojan_udp(ws, rest):
    # Trojan UDP: 每个包 [atyp][addr][port:2][len:2][CRLF][payload], 目标可变
    loop = asyncio.get_running_loop()
    sess = _UdpSession()
    socks = {}
    buf = bytearray(rest)

    async def get_tr(fam):
        tr = socks.get(fam)
        if tr is None:
            local = ('::', 0) if fam == socket.AF_INET6 else ('0.0.0.0', 0)
            tr, _ = await loop.create_datagram_endpoint(lambda: _UdpProto(sess.on_data), local_addr=local, family=fam)
            socks[fam] = tr
            sess.transports.append(tr)
        return tr

    async def flush():
        while buf:
            try:
                host, off = _parse_addr(buf, 0, 1, 3, 4)
                _need(buf, off, 4)
                port, n = struct.unpack('!HH', buf[off:off + 4])
                off += 4
                if buf[off:off + 2] == b'\r\n':
                    off += 2
                _need(buf, off, n)
            except _Short:
                return
            payload = bytes(buf[off:off + n])
            del buf[:off + n]
            sess.last = time.time()
            if is_blocked_domain(host):
                continue
            try:
                fam, ip = (await resolve_addrs(host))[0]
                tr = await get_tr(fam)
                tr.sendto(payload, (ip, port))
            except Exception as e:
                if DEBUG:
                    logger.error(f'Trojan UDP send error: {e}')

    async def up():
        await flush()
        async for msg in ws:
            if msg.type != aiohttp.WSMsgType.BINARY:
                break
            buf.extend(msg.data)
            await flush()

    async def down():
        while True:
            data, addr = await sess.q.get()
            hdr = _pack_trojan_addr(addr[0], addr[1])
            await ws.send_bytes(hdr + struct.pack('!H', len(data)) + b'\r\n' + data)

    try:
        await _finish([asyncio.ensure_future(up()), asyncio.ensure_future(down()), asyncio.ensure_future(sess.idle_watch())])
    finally:
        sess.close()


def _pack_mux_addr(ip, port):
    # Mux.Cool 地址格式: [port:2][atyp: 1=v4 2=域名 3=v6][addr]
    a = ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    if a.version == 4:
        return struct.pack('!H', port) + b'\x01' + a.packed
    return struct.pack('!H', port) + b'\x03' + a.packed


def _make_udp_sock():
    # 优先 IPv6 双栈(显式关闭 V6ONLY, 同时收发 IPv4), 容器没有 IPv6 时退回 IPv4
    try:
        sk = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except OSError:
        sk = None
    if sk is not None:
        try:
            sk.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sk.bind(('::', 0))
            sk.setblocking(False)
            return sk, socket.AF_INET6
        except OSError:
            sk.close()
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.bind(('0.0.0.0', 0))
    sk.setblocking(False)
    return sk, socket.AF_INET


async def relay_vless_mux(ws, rest):
    # VLESS cmd=3: Mux.Cool / XUDP (Xray 客户端 VLESS UDP 默认走 XUDP)
    # 帧: [meta_len:2][sid:2][status:1][opt:1][network:1 + port:2 + addr ...][len:2][data]
    # status: 1=New 2=Keep 3=End 4=KeepAlive ; opt&1=带数据 ; network: 1=TCP 2=UDP
    loop = asyncio.get_running_loop()
    buf = bytearray(rest)
    sessions = {}
    send_lock = asyncio.Lock()
    tasks = set()
    state = {'last': time.time()}

    async def send_frame(meta, data=b''):
        frame = struct.pack('!H', len(meta)) + meta
        if data:
            frame += struct.pack('!H', len(data)) + data
        async with send_lock:
            await ws.send_bytes(frame)

    def close_sess(sid, notify=True):
        sess = sessions.pop(sid, None)
        if sess is None:
            return
        try:
            if sess['tr'] is not None:
                sess['tr'].close()
        except Exception:
            pass
        if notify and not ws.closed:
            t = asyncio.ensure_future(send_frame(struct.pack('!HBB', sid, 3, 0)))
            tasks.add(t)
            t.add_done_callback(tasks.discard)

    async def tcp_reader(sid, reader):
        try:
            while True:
                data = await reader.read(min(BUF_SIZE, 65000))
                if not data:
                    break
                state['last'] = time.time()
                await send_frame(struct.pack('!HBB', sid, 2, 1), data)
        except Exception:
            pass
        close_sess(sid)

    async def tcp_connect(sid, sess, host, port):
        try:
            reader, writer = await open_target(host, port)
        except Exception as e:
            if DEBUG:
                logger.error(f'Mux connect error {host}:{port}: {e}')
            close_sess(sid)
            return
        if sessions.get(sid) is not sess:
            writer.close()
            return
        sess['tr'] = writer
        for d in sess.pop('pending', []):
            writer.write(d)
        await tcp_reader(sid, reader)

    def tcp_write(sess, data):
        if sess['tr'] is None:
            sess['pending'].append(data)
        else:
            sess['tr'].write(data)

    async def open_sess(sid, network, host, port):
        if is_blocked_domain(host):
            await send_frame(struct.pack('!HBB', sid, 3, 0))
            return
        if network == 1:
            # 后台建连, 不阻塞同一条 Mux 连接上的其他会话; 建连前收到的数据先缓存
            sess = {'net': 1, 'tr': None, 'pending': []}
            sessions[sid] = sess
            t = asyncio.ensure_future(tcp_connect(sid, sess, host, port))
            tasks.add(t)
            t.add_done_callback(tasks.discard)
            return
        if not ENABLE_UDP:
            await send_frame(struct.pack('!HBB', sid, 3, 0))
            return

        def on_udp(data, addr, sid=sid):
            state['last'] = time.time()
            meta = struct.pack('!HBBB', sid, 2, 1, 2) + _pack_mux_addr(addr[0], addr[1])
            t = asyncio.ensure_future(send_frame(meta, data[:65000]))
            tasks.add(t)
            t.add_done_callback(tasks.discard)

        sk, fam = _make_udp_sock()
        tr, _ = await loop.create_datagram_endpoint(lambda: _UdpProto(on_udp), sock=sk)
        sessions[sid] = {'net': 2, 'tr': tr, 'fam': fam}

    async def udp_send(sid, host, port, data):
        sess = sessions.get(sid)
        if sess is None or is_blocked_domain(host):
            return
        addrs = await resolve_addrs(host)
        if sess['fam'] == socket.AF_INET:
            addrs = [a for a in addrs if a[0] == socket.AF_INET]
            if not addrs:
                return
        ip = addrs[0][1]
        if sess['fam'] == socket.AF_INET6 and ':' not in ip:
            ip = '::ffff:' + ip
        sess['tr'].sendto(data, (ip, port))

    async def handle_frame(meta, data):
        sid, status, opt = struct.unpack('!HBB', meta[:4])
        dest = None
        if len(meta) > 4 and status in (1, 2):
            network = meta[4]
            port = struct.unpack('!H', meta[5:7])[0]
            host, _off = _parse_addr(meta, 7, 1, 2, 3)
            dest = (network, host, port)
        if status == 1:
            if dest is None:
                return
            try:
                await open_sess(sid, dest[0], dest[1], dest[2])
            except Exception as e:
                if DEBUG:
                    logger.error(f'Mux open error {dest[1]}:{dest[2]}: {e}')
                await send_frame(struct.pack('!HBB', sid, 3, 0))
                return
            sess = sessions.get(sid)
            if sess and data:
                if sess['net'] == 2:
                    await udp_send(sid, dest[1], dest[2], data)
                else:
                    tcp_write(sess, data)
            if sess and sess['net'] == 2:
                sess['dest'] = dest
            return
        if status == 2:
            sess = sessions.get(sid)
            if sess is None or not data:
                return
            if sess['net'] == 2:
                d = dest or sess.get('dest')
                if d:
                    await udp_send(sid, d[1], d[2], data)
            else:
                tcp_write(sess, data)
            return
        if status == 3:
            close_sess(sid, notify=False)

    async def up():
        async for msg in ws:
            if msg.type != aiohttp.WSMsgType.BINARY:
                break
            buf.extend(msg.data)
            state['last'] = time.time()
            await drain_buf()

    async def drain_buf():
        while len(buf) >= 2:
            ml = struct.unpack('!H', buf[:2])[0]
            if ml < 4:
                raise ValueError('bad mux meta')
            if len(buf) < 2 + ml:
                return
            meta = bytes(buf[2:2 + ml])
            end = 2 + ml
            data = b''
            if meta[3] & 1:
                if len(buf) < end + 2:
                    return
                dl = struct.unpack('!H', buf[end:end + 2])[0]
                if len(buf) < end + 2 + dl:
                    return
                data = bytes(buf[end + 2:end + 2 + dl])
                end += 2 + dl
            del buf[:end]
            try:
                await handle_frame(meta, data)
            except (_Short, ValueError, UnicodeDecodeError, IndexError, struct.error):
                pass

    async def idle_watch():
        while True:
            await asyncio.sleep(15)
            if not sessions and time.time() - state['last'] > UDP_IDLE_TIMEOUT:
                return

    try:
        await drain_buf()
        await _finish([asyncio.ensure_future(up()), asyncio.ensure_future(idle_watch())])
    finally:
        for sid in list(sessions):
            close_sess(sid, notify=False)
        for t in list(tasks):
            t.cancel()


async def handle_vless(ws, msg):
    # 处理VLS协议, 不是 VLESS 返回 False
    try:
        hdr = parse_vless_header(msg)
    except (_Short, ValueError, UnicodeDecodeError):
        return False
    if hdr is None:
        return False
    cmd, host, port, off = hdr
    if cmd not in (1, 2, 3) or (cmd == 2 and not ENABLE_UDP):
        return True
    if cmd != 3 and is_blocked_domain(host):
        return True
    try:
        if cmd == 3:
            await ws.send_bytes(b'\x00\x00')
            await relay_vless_mux(ws, msg[off:])
            return True
        if cmd == 2:
            await ws.send_bytes(b'\x00\x00')
            await relay_vless_udp(ws, host, port, msg[off:])
            return True
        reader, writer = await open_target(host, port)
    except Exception as e:
        if DEBUG:
            logger.error(f'VLESS connect error {host}:{port}: {e}')
        return True
    try:
        await ws.send_bytes(b'\x00\x00')
        if off < len(msg):
            writer.write(msg[off:])
        await relay_tcp(ws, reader, writer)
    except Exception as e:
        if DEBUG:
            logger.error(f'VLESS relay error: {e}')
    return True


async def handle_trojan(ws, msg):
    # 处理Tro协议, 不是 Trojan 返回 False
    try:
        hdr = parse_trojan_header(msg)
    except (_Short, ValueError, UnicodeDecodeError):
        return False
    if hdr is None:
        return False
    cmd, host, port, off = hdr
    if cmd not in (1, 3) or (cmd == 3 and not ENABLE_UDP):
        return True
    try:
        if cmd == 3:
            await relay_trojan_udp(ws, msg[off:])
            return True
        if is_blocked_domain(host):
            return True
        reader, writer = await open_target(host, port)
    except Exception as e:
        if DEBUG:
            logger.error(f'Tro connect error {host}:{port}: {e}')
        return True
    try:
        if off < len(msg):
            writer.write(msg[off:])
        await relay_tcp(ws, reader, writer)
    except Exception as e:
        if DEBUG:
            logger.error(f'Tro relay error: {e}')
    return True


def _early_data(request):
    # 支持客户端 path 里的 ?ed=2048: 首包放在 Sec-WebSocket-Protocol 头里, 省一个 RTT
    proto = request.headers.get('Sec-WebSocket-Protocol', '').strip()
    if not proto or ',' in proto or len(proto) < 20:
        return None, ()
    try:
        data = base64.urlsafe_b64decode(proto + '=' * (-len(proto) % 4))
    except Exception:
        return None, ()
    return (data or None), (proto,)


async def websocket_handler(request):
    if request.headers.get('Upgrade', '').lower() != 'websocket':
        return web.Response(status=404, text='Not Found\n')

    early, protocols = _early_data(request)
    ws = web.WebSocketResponse(compress=False, heartbeat=WS_HEARTBEAT, protocols=protocols, max_msg_size=0)
    await ws.prepare(request)

    try:
        if early:
            msg_data = early
        else:
            first = await asyncio.wait_for(ws.receive(), timeout=5)
            if first.type != aiohttp.WSMsgType.BINARY:
                await ws.close()
                return ws
            msg_data = first.data

        handled = False
        if len(msg_data) > 17 and msg_data[0] == 0:
            handled = await handle_vless(ws, msg_data)   # 尝试VLS
        if not handled and len(msg_data) >= 58:
            handled = await handle_trojan(ws, msg_data)  # 尝试Tro
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        if DEBUG:
            logger.error(f'WebSocket handler error: {e}')
    finally:
        if not ws.closed:
            await ws.close()
    return ws


async def http_handler(request):
    global INDEX_HTML
    if request.path == '/':
        if INDEX_HTML is None:
            try:
                with open('index.html', 'r', encoding='utf-8') as f:
                    INDEX_HTML = f.read()
            except OSError:
                INDEX_HTML = 'Hello world!'
        return web.Response(text=INDEX_HTML, content_type='text/html')

    if request.path == f'/{SUB_PATH}':
        base64_content = await build_subscription()
        return web.Response(text=base64_content + '\n', content_type='text/plain', headers=sub_headers())

    return web.Response(status=404, text='Not Found\n')


def sub_headers():
    # 订阅名称 = NAME: 客户端导入订阅时显示的名称(Profile-Title / Content-Disposition)
    if not NAME:
        return {}
    try:
        NAME.encode('ascii')
        title = NAME
    except UnicodeEncodeError:
        title = 'base64:' + base64.b64encode(NAME.encode('utf-8')).decode()
    return {
        'Profile-Title': title,
        'Content-Disposition': f"inline; filename*=UTF-8''{quote(NAME)}",   # inline: 浏览器直接显示,不弹出下载
    }


async def build_subscription():
    await get_isp()
    await get_ip()

    name_part = f"{NAME}-{ISP}" if NAME else ISP
    has_domain = bool(DOMAIN) and DOMAIN != 'your-domain.com'
    nodes = []
    ws_path = quote('/' + WSPATH + '?ed=2048', safe='')

    if has_domain:
        # CDN节点: 连接地址用 CFIP:CFPORT(CFIP留空则用DOMAIN), SNI/Host 是自己的域名
        cdn_host = _fmt_host(CFIP) if CFIP else DOMAIN
        nodes.append(f"vless://{UUID}@{cdn_host}:{CFPORT}?encryption=none&security=tls&sni={DOMAIN}&fp=chrome&type=ws&host={DOMAIN}&path={ws_path}#{name_part}-VLESS-CDN")
        nodes.append(f"trojan://{UUID}@{cdn_host}:{CFPORT}?security=tls&sni={DOMAIN}&fp=chrome&type=ws&host={DOMAIN}&path={ws_path}#{name_part}-Trojan-CDN")

        # vless-ws 直连节点: 自动获取的公网IP + 实际监听端口(无TLS)
        ip = await get_public_ip()
        if ip:
            host = _fmt_host(ip)
            nodes.append(f"vless://{UUID}@{host}:{ActualPort}?encryption=none&security=none&type=ws&host={host}&path={ws_path}#{name_part}-VLESS-WS")
    else:
        # 无域名: 公网IP + 实际监听端口(无TLS); 获取不到IP时 CurrentDomain 为占位符,提醒设置 DOMAIN
        tls_param = 'tls' if Tls == 'tls' else 'none'
        nodes.append(f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none&security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path={ws_path}#{name_part}-VLESS-WS")
        nodes.append(f"trojan://{UUID}@{CurrentDomain}:{CurrentPort}?security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path={ws_path}#{name_part}-Trojan-WS")

    subscription = "\n".join(nodes)
    return base64.b64encode(subscription.encode()).decode()

# =========================== Telegram 推送 ===========================


async def send_telegram():
    if not BOT_TOKEN or not CHAT_ID:
        logger.info('TG variables is empty, Skipping push nodes to TG')
        return
    try:
        message = await build_subscription()
        url = f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage'
        escaped_name = re.sub(r'[_*\[\]()~`>#+=|{}.!-]', r'\\\g<0>', NAME)
        params = {
            'chat_id': CHAT_ID,
            'text': f'**{escaped_name}节点推送通知**\n```{message}```',
            'parse_mode': 'MarkdownV2'
        }
        async with _session().post(url, params=params, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                logger.info('Telegram message sent successfully')
            else:
                logger.error(f'Failed to send Telegram message: HTTP {resp.status}')
    except Exception as e:
        logger.error(f'Failed to send Telegram message: {e}')

# =========================== 探针 (CF-Server-Monitor) ===========================
def log(msg):
    logger.info(msg)

def log_error(msg):
    logger.error(msg)

def log_debug(msg):
    logger.debug(msg)

def _http_get_text(url, timeout=3):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', 'ignore')

def _looks_like_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def _fetch_public_ip_version(version='v4', timeout=3):
    host = 'ipv4.ip.sb' if version == 'v4' else 'ipv6.ip.sb'
    try:
        ip = _http_get_text(f'http://{host}', timeout).strip()
        if ip and _looks_like_ip(ip):
            return ip
    except Exception:
        pass
    try:
        result = subprocess.run(['curl', '-sm', str(int(timeout) + 2), host],
                                capture_output=True, text=True, timeout=timeout + 3)
        ip = result.stdout.strip()
        if ip and _looks_like_ip(ip):
            return ip
    except Exception:
        pass
    return None

def _probe_read_cpu_times():
    with open('/proc/stat') as f:
        parts = f.readline().split()
    nums = list(map(int, parts[1:9]))
    idle = nums[3] + nums[4]
    total = sum(nums)
    return idle, total

def _probe_cpu_percent(prev_idle, prev_total):
    idle, total = _probe_read_cpu_times()
    d_idle = idle - prev_idle
    d_total = total - prev_total
    if d_total <= 0:
        return 0.0, idle, total
    usage = (1 - d_idle / d_total) * 100
    return round(max(0.0, min(100.0, usage)), 2), idle, total

def _probe_read_host_meminfo():
    info = {}
    with open('/proc/meminfo') as f:
        for line in f:
            key, val = line.split(':', 1)
            info[key.strip()] = int(val.strip().split()[0])
    ram_total = info.get('MemTotal', 0) // 1024
    ram_free = info.get('MemAvailable', info.get('MemFree', 0)) // 1024
    ram_used = max(0, ram_total - ram_free)
    swap_total = info.get('SwapTotal', 0) // 1024
    swap_free = info.get('SwapFree', 0) // 1024
    swap_used = max(0, swap_total - swap_free)
    return ram_total, ram_used, swap_total, swap_used

def _probe_read_cgroup_memory():
    try:
        with open('/sys/fs/cgroup/memory.current') as f:
            used = int(f.read().strip())
        with open('/sys/fs/cgroup/memory.max') as f:
            raw = f.read().strip()
        limit = None if raw == 'max' else int(raw)
        swap_used = swap_total = 0
        try:
            with open('/sys/fs/cgroup/memory.swap.current') as f:
                swap_used = int(f.read().strip())
            with open('/sys/fs/cgroup/memory.swap.max') as f:
                raw_sw = f.read().strip()
            swap_total = None if raw_sw == 'max' else int(raw_sw)
        except OSError:
            pass
        return used, limit, swap_used, swap_total
    except OSError:
        pass
    try:
        with open('/sys/fs/cgroup/memory/memory.usage_in_bytes') as f:
            used = int(f.read().strip())
        with open('/sys/fs/cgroup/memory/memory.limit_in_bytes') as f:
            limit = int(f.read().strip())
        if limit > (1 << 62):
            limit = None
        swap_used = swap_total = 0
        try:
            with open('/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes') as f:
                memsw_used = int(f.read().strip())
            with open('/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes') as f:
                memsw_limit = int(f.read().strip())
            swap_used = max(0, memsw_used - used)
            if memsw_limit <= (1 << 62) and limit is not None:
                swap_total = max(0, memsw_limit - limit)
        except OSError:
            pass
        return used, limit, swap_used, swap_total
    except OSError:
        pass
    return None, None, None, None

def _probe_read_meminfo():
    used, limit, swap_used, swap_total = _probe_read_cgroup_memory()
    if used is not None and limit:
        ram_total = limit // (1024 * 1024)
        ram_used = min(used // (1024 * 1024), ram_total)
        swap_total_mb = (swap_total or 0) // (1024 * 1024)
        swap_used_mb = min((swap_used or 0) // (1024 * 1024), swap_total_mb) if swap_total_mb else 0
        return ram_total, ram_used, swap_total_mb, swap_used_mb
    return _probe_read_host_meminfo()

def _probe_read_disk_usage(path='/'):
    st = os.statvfs(path)
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    used = total - free
    return total // (1024 * 1024), used // (1024 * 1024)

def _probe_read_net_bytes():
    rx_total = tx_total = 0
    with open('/proc/net/dev') as f:
        lines = f.readlines()[2:]
    for line in lines:
        iface, rest = line.split(':', 1)
        if iface.strip() == 'lo':
            continue
        fields = rest.split()
        rx_total += int(fields[0])
        tx_total += int(fields[8])
    return rx_total, tx_total

def _probe_read_boot_time_ms():
    with open('/proc/stat') as f:
        for line in f:
            if line.startswith('btime'):
                return int(line.split()[1]) * 1000
    return 0

def _probe_read_os_name():
    try:
        info = {}
        with open('/etc/os-release') as f:
            for line in f:
                line = line.strip()
                if not line or '=' not in line:
                    continue
                key, val = line.split('=', 1)
                info[key] = val.strip('"')
        pretty = info.get('PRETTY_NAME')
        if pretty:
            return pretty
        name = info.get('NAME')
        version = info.get('VERSION') or info.get('VERSION_ID')
        if name:
            return f'{name} {version}'.strip() if version else name
    except OSError:
        pass
    return f'{platform.system()} {platform.release()}'

def _probe_read_cpu_info():
    model = ''
    try:
        with open('/proc/cpuinfo') as f:
            for line in f:
                if line.lower().startswith('model name'):
                    model = line.split(':', 1)[1].strip()
                    break
    except OSError:
        pass
    return model or platform.processor() or 'unknown'

def _probe_read_process_count():
    try:
        return sum(1 for p in os.listdir('/proc') if p.isdigit())
    except OSError:
        return 0

def _probe_read_conn_count(proto):
    # 同时统计 IPv4 和 IPv6 (tcp + tcp6 / udp + udp6)
    total = 0
    for name in (proto, proto + '6'):
        try:
            with open(f'/proc/net/{name}') as f:
                total += max(0, sum(1 for _ in f) - 1)
        except OSError:
            pass
    return total

def _probe_load_avg():
    la = os.getloadavg()
    return f'{la[0]:.2f} {la[1]:.2f} {la[2]:.2f}'

_probe_ip_cache = {'v4': '0', 'v6': '0', 'ts': 0}

def _probe_get_public_ips():
    now = time.time()
    if now - _probe_ip_cache['ts'] < PROBE_IP_REFRESH_INTERVAL and _probe_ip_cache['ts'] > 0:
        return _probe_ip_cache['v4'], _probe_ip_cache['v6']

    v4 = _fetch_public_ip_version('v4') or '0'
    v6 = _fetch_public_ip_version('v6') or '0'

    _probe_ip_cache['v4'] = v4
    _probe_ip_cache['v6'] = v6
    _probe_ip_cache['ts'] = now
    return v4, v6

def _probe_parse_host_port(target, default_port=80):
    target = (target or '').strip()
    if not target:
        return None, None
    if target.startswith('['):
        m = re.match(r'^\[([^\]]+)\](?::(\d+))?$', target)
        if m:
            return m.group(1), int(m.group(2)) if m.group(2) else default_port
        return target.strip('[]'), default_port
    if ':' in target and target.count(':') == 1:
        host, port = target.split(':', 1)
        try:
            return host, int(port)
        except ValueError:
            return target, default_port
    return target, default_port

def _probe_tcp_ping(target, count=4, timeout=1.5):
    host, port = _probe_parse_host_port(target, default_port=443)
    if not host:
        return None, None
    times = []
    failures = 0
    for _ in range(max(1, count)):
        start = time.time()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                times.append((time.time() - start) * 1000)
        except OSError:
            failures += 1
    total = max(1, count)
    loss = round(failures / total * 100, 2)
    if not times:
        return None, loss
    return round(sum(times) / len(times), 2), loss

def _probe_collect(prev_idle, prev_total, prev_rx, prev_tx, prev_ts):
    cpu, idle, total = _probe_cpu_percent(prev_idle, prev_total)
    ram_total, ram_used, swap_total, swap_used = _probe_read_meminfo()
    disk_total, disk_used = _probe_read_disk_usage('/')
    rx, tx = _probe_read_net_bytes()

    now = time.time()
    dt = max(1e-6, now - prev_ts)
    rx_speed = max(0, int((rx - prev_rx) / dt))
    tx_speed = max(0, int((tx - prev_tx) / dt))

    metrics = {
        'cpu': cpu,
        'ram_total': ram_total,
        'ram_used': ram_used,
        'swap_total': swap_total,
        'swap_used': swap_used,
        'disk_total': disk_total,
        'disk_used': disk_used,
        'load_avg': _probe_load_avg(),
        'boot_time': str(_probe_read_boot_time_ms()),
        'net_rx': str(rx),
        'net_tx': str(tx),
        'net_rx_monthly': str(rx),
        'net_tx_monthly': str(tx),
        'net_in_speed': str(rx_speed),
        'net_out_speed': str(tx_speed),
        'os': _probe_read_os_name(),
        'arch': platform.machine(),
        'kernel_version': platform.release(),
        'cpu_info': _probe_read_cpu_info(),
        'cpu_cores': str(os.cpu_count() or 1),
        'processes': str(_probe_read_process_count()),
        'tcp_conn': str(_probe_read_conn_count('tcp')),
        'udp_conn': str(_probe_read_conn_count('udp')),
        'version': PROBE_AGENT_VERSION,
        'agent_version': PROBE_AGENT_VERSION,
    }

    ip_v4, ip_v6 = _probe_get_public_ips()
    metrics['ip_v4'] = ip_v4
    metrics['ip_v6'] = ip_v6

    # 三网 ping 降频：缓存未过期则复用
    global _probe_ping_cache
    if now - _probe_ping_cache['ts'] >= PROBE_PING_CACHE_TTL:
        if PROBE_CT:
            ping_ct, loss_ct = _probe_tcp_ping(PROBE_CT, PROBE_PING_COUNT, PROBE_PING_TIMEOUT)
            _probe_ping_cache['ping_ct'] = ping_ct
            _probe_ping_cache['loss_ct'] = loss_ct
        if PROBE_CU:
            ping_cu, loss_cu = _probe_tcp_ping(PROBE_CU, PROBE_PING_COUNT, PROBE_PING_TIMEOUT)
            _probe_ping_cache['ping_cu'] = ping_cu
            _probe_ping_cache['loss_cu'] = loss_cu
        if PROBE_CM:
            ping_cm, loss_cm = _probe_tcp_ping(PROBE_CM, PROBE_PING_COUNT, PROBE_PING_TIMEOUT)
            _probe_ping_cache['ping_cm'] = ping_cm
            _probe_ping_cache['loss_cm'] = loss_cm
        _probe_ping_cache['ts'] = now

    if PROBE_CT:
        metrics['ping_ct'] = _probe_ping_cache['ping_ct']
        metrics['loss_ct'] = _probe_ping_cache['loss_ct']
    if PROBE_CU:
        metrics['ping_cu'] = _probe_ping_cache['ping_cu']
        metrics['loss_cu'] = _probe_ping_cache['loss_cu']
    if PROBE_CM:
        metrics['ping_cm'] = _probe_ping_cache['ping_cm']
        metrics['loss_cm'] = _probe_ping_cache['loss_cm']

    return metrics, idle, total, rx, tx, now

PROBE_AGENT_VERSION = os.environ.get('PROBE_AGENT_VERSION', 'python')

def _probe_report(metrics):
    try:
        body = json.dumps({'id': PROBE_ID, 'secret': PROBE_SECRET, 'metrics': metrics}).encode()
        req = urllib.request.Request(PROBE_URL, data=body, method='POST', headers={
            'Content-Type': 'application/json',
            'X-Agent-Version': PROBE_AGENT_VERSION,
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode('utf-8', 'ignore')
            log(f'[probe] report -> HTTP {resp.status}' + (f': {text[:200]}' if text else ''))
    except Exception as e:
        log_error(f'[probe] report failed: {e}')

def start_probe_loop():
    if not (PROBE_ID and PROBE_SECRET and PROBE_URL):
        log('PROBE variable is empty, skipping probe')
        return

    def loop():
        idle, total = _probe_read_cpu_times()
        rx, tx = _probe_read_net_bytes()
        ts = time.time()
        log(f'[probe] reporting to {PROBE_URL} every {PROBE_INTERVAL}s')
        while True:
            time.sleep(PROBE_INTERVAL)
            try:
                metrics, idle_, total_, rx_, tx_, ts_ = _probe_collect(idle, total, rx, tx, ts)
                idle, total, rx, tx, ts = idle_, total_, rx_, tx_, ts_
                _probe_report(metrics)
            except Exception as e:
                log_error(f'[probe] collection failed: {e}')

    t = threading.Thread(target=loop, daemon=True)
    t.start()

# =========================== 探针 WSS 实时上报 ===========================
def _pip_install(package):
    """用当前解释器的pip安装package,先尝试普通安装,PEP668环境(externally-managed-environment)
    再补--break-system-packages重试一次;返回(是否成功, 最后一次报错信息)"""
    py = sys.executable
    attempts = [
        [py, '-m', 'pip', 'install', '--user', '-q', package],
        [py, '-m', 'pip', 'install', '--user', '--break-system-packages', '-q', package],
    ]
    last_err = ''
    for cmd in attempts:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            if result.returncode == 0:
                return True, ''
            last_err = (result.stderr or result.stdout or '').strip()
        except Exception as e:
            last_err = str(e)
    return False, last_err

def _ensure_ws_client():
    """确保 websocket-client 可用;缺失时尝试自动pip安装并在当前进程内直接加载,无需重启"""
    global _ws_client, _WS_AVAILABLE
    if _WS_AVAILABLE:
        return True

    log('[probe] websocket-client not found, attempting automatic install for real-time WSS reporting...')
    ok, err = _pip_install('websocket-client')
    if not ok:
        log_error(f'[probe] automatic install failed, staying on POST polling: {err[:300]}')
        return False

    try:
        import site
        import importlib
        user_site = site.getusersitepackages()
        if user_site not in sys.path:
            sys.path.insert(0, user_site)
        importlib.invalidate_caches()
        import websocket as _wsmod
        _ws_client = _wsmod
        _WS_AVAILABLE = True
        log('[probe] websocket-client installed and loaded, switching to real-time WSS reporting')
        return True
    except Exception as e:
        log_error(f'[probe] websocket-client installed but failed to load in this process: {e}')
        return False

def _probe_ws_url():
    """把 PROBE_URL 的 http(s) 换成 ws(s),路径不变(官方协议同一路径区分POST和Upgrade)"""
    parsed = urlparse(PROBE_URL)
    scheme = 'wss' if parsed.scheme == 'https' else 'ws'
    return f'{scheme}://{parsed.netloc}{parsed.path}'

def start_probe_ws_loop():
    """优先走WSS长连接实现秒级实时上报;websocket-client未安装、被禁用或连接持续失败时,
    自动退回start_probe_loop()的POST轮询(60秒一次),行为不会比原来差"""
    if not (PROBE_ID and PROBE_SECRET and PROBE_URL):
        log('PROBE variable is empty, skipping probe')
        return

    if not PROBE_WSS:
        log('[probe] PROBE_WSS is false, using POST polling only')
        start_probe_loop()
        return

    if not _WS_AVAILABLE and not _ensure_ws_client():
        log('[probe] websocket-client unavailable, falling back to POST polling')
        start_probe_loop()
        return

    ws_url = _probe_ws_url()

    def loop():
        idle, total = _probe_read_cpu_times()
        rx, tx = _probe_read_net_bytes()
        ts = time.time()
        backoff = 5
        consecutive_failures = 0
        log(f'[probe] attempting WSS real-time reporting to {ws_url}')
        while True:
            ws = None
            try:
                ws = _ws_client.create_connection(
                    ws_url,
                    timeout=15,
                    header=[
                        f'X-Agent-Version: {PROBE_AGENT_VERSION}',
                        'User-Agent: cfsm',
                        'X-Agent-Config-Schema: 6',
                        'X-Agent-Config-Md5: none',
                    ],
                )
                ws.settimeout(30)
                ws.recv()  # 消费握手后的 hello 帧
                log('[probe] WSS connected')
                backoff = 5
                consecutive_failures = 0

                while True:
                    metrics, idle, total, rx, tx, ts = _probe_collect(idle, total, rx, tx, ts)
                    ws.send(json.dumps({'id': PROBE_ID, 'secret': PROBE_SECRET, 'metrics': metrics}))
                    log_debug('[probe] WSS metrics sent')

                    next_wait = PROBE_INTERVAL
                    try:
                        raw = ws.recv()
                        log_debug(f'[probe] raw ack: {raw}')
                        resp = json.loads(raw)
                        if resp.get('type') == 'error':
                            log_error(f"[probe] WSS error: {resp.get('error')} (code {resp.get('code')})")
                            raise RuntimeError('protocol error')
                        next_ms = resp.get('nextWssReportAfterMs')
                        if isinstance(next_ms, (int, float)) and next_ms > 0:
                            next_wait = max(1, next_ms / 1000)
                        log_debug(f'[probe] next report in {next_wait}s')
                    except (ValueError, RuntimeError):
                        raise
                    except Exception:
                        pass  # ack解析失败不致命,按默认间隔继续

                    time.sleep(next_wait)
            except Exception as e:
                consecutive_failures += 1
                log_error(f'[probe] WSS connection issue: {e}')
                try:
                    if ws:
                        ws.close()
                except Exception:
                    pass
                # 连续失败多次就先退回POST轮询上报几轮,同时仍会定期重试WSS
                if consecutive_failures >= 5:
                    log_error('[probe] WSS repeatedly failing, falling back to POST polling for this cycle')
                    try:
                        metrics, idle, total, rx, tx, ts = _probe_collect(idle, total, rx, tx, ts)
                        _probe_report(metrics)
                    except Exception as e2:
                        log_error(f'[probe] fallback POST also failed: {e2}')
                    time.sleep(PROBE_INTERVAL)
                else:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 120)

    t = threading.Thread(target=loop, daemon=True)
    t.start()


async def add_access_task():
    if not AUTO_ACCESS or not DOMAIN:
        return

    # 只提交首页地址用于保活,不包含订阅路径,避免订阅地址泄露给第三方
    full_url = f"https://{DOMAIN}"
    try:
        async with _session().post("https://oooo.serv00.net/add-url", json={"url": full_url}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            await resp.read()
        logger.info('Automatic Access Task added successfully')
    except Exception as e:
        logger.error(f'Add URL failed: {e}')


async def main():
    global ActualPort
    validate_config()
    _raise_nofile_limit()
    actual_port = PORT

    # 检查端口是否可用，如果不可用则查找可用端口
    if not is_port_available(actual_port):
        logger.warning(f"Port {actual_port} is already in use, finding available port...")
        new_port = find_available_port(actual_port + 1)
        if new_port:
            actual_port = new_port
            logger.info(f"Using port {actual_port} instead of {PORT}")
        else:
            always_log("No available ports found")
            sys.exit(1)

    ActualPort = actual_port

    app = web.Application()

    # 路由
    app.router.add_get('/', http_handler)
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)

    # 启动服务
    runner = web.AppRunner(app, access_log=None, handle_signals=False)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', actual_port, reuse_address=True, backlog=1024)
    await site.start()
    always_log(f"✅ server is running on port {actual_port}")
    # 放到线程里启动: 缺少 websocket-client 时会同步 pip 安装(最久约3分钟),直接调用会卡住事件循环
    threading.Thread(target=start_probe_ws_loop, daemon=True).start()
    if RESTARTS == 0:
        await send_telegram()
        await add_access_task()

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        await stop.wait()
    finally:
        await runner.cleanup()
        if HTTP is not None and not HTTP.closed:
            await HTTP.close()

# =========================== 进程守护 ===========================


def _run_server():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")


def _supervise():
    # 父进程只负责拉起子进程; 子进程意外退出自动重启(指数退避, 最长30秒); 配置错误(退出码2)不重启
    state = {'stop': False, 'proc': None}

    def _on_signal(signum, frame):
        state['stop'] = True
        p = state['proc']
        if p is not None and p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    restarts = 0
    backoff = 1
    while True:
        env = dict(os.environ)
        env['_APP_WS_CHILD'] = '1'
        env['_APP_WS_RESTARTS'] = str(restarts)
        started = time.time()
        try:
            state['proc'] = subprocess.Popen([sys.executable] + sys.argv, env=env)
        except Exception as e:
            always_log(f'⚠️ 守护进程启动子进程失败({e}), 改为直接运行')
            _run_server()
            return
        rc = state['proc'].wait()
        if state['stop']:
            sys.exit(0)
        if rc == 2:
            always_log('❌ 配置错误, 守护进程不再重启, 请检查变量后重新运行')
            sys.exit(2)
        if time.time() - started > 60:
            backoff = 1
        restarts += 1
        always_log(f'⚠️ 服务进程退出(code {rc}), {backoff} 秒后自动重启(第 {restarts} 次)')
        time.sleep(backoff)
        backoff = min(backoff * 2, 30)


if __name__ == '__main__':
    _can_supervise = DAEMON and not os.environ.get('_APP_WS_CHILD') and sys.argv and os.path.isfile(sys.argv[0])
    if _can_supervise:
        _supervise()
    else:
        _run_server()
