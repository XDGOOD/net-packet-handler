#!/usr/bin/env python3
"""
AEGS v2 Protocol - Cross-Platform Client Proxy & Management Tool
High-Performance Zero-DPI WireGuard UDP Obfuscator (Linux, macOS, Windows)

Features:
- Native binary supervisor with auto-detection & fallback
- Integrated pure-Python ChaCha20-Poly1305 wire-compatible fallback engine
- KeyID calculator & token validator (PBKDF2 / HKDF-SHA256)
- Automated WireGuard config generation
- Interactive setup wizard
"""

from __future__ import annotations
import os
import sys
import time
import socket
import select
import struct
import secrets
import hashlib
import argparse
import subprocess
from pathlib import Path

# Safe encoding configuration for Windows terminals
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# --- Protocol Constants ---
VER_MAGIC = b"AG2\x01"
DEFAULT_LOCAL_PORT = 51821
DEFAULT_SERVER_PORT = 50001
PBKDF2_ITERATIONS = 200000
BUFFER_SIZE = 65535
PAD_MIN = 32
PAD_MAX = 256
FRAME_HDR = 2
TAG_LEN = 16

# --- Colors for Terminal ---
class Colors:
    CYAN = "\033[0;36m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    RED = "\033[0;31m"
    WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        cls.CYAN = cls.GREEN = cls.YELLOW = cls.RED = cls.WHITE = cls.BOLD = cls.DIM = cls.RESET = ""

if os.name == 'nt' and not os.environ.get('TERM'):
    try:
        import colorama
        colorama.init()
    except ImportError:
        pass

def banner():
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print(r"""
    ___    ______ _____ ____         ____        __  __              
   /   |  / ____// ___// __ \ _   __/ __ \__  __/ /_/ /_  ____  ____ 
  / /| | / __/  / / _ / / / /| | / / /_/ / / / / __/ __ \/ __ \/ __ \
 / ___ |/ /___ / /_/ // /_/ / | |/ / ____/ /_/ / /_/ / / / /_/ / / / /
/_/  |_/_____/ \____(_)____/  |___/_/    \__, /\__/_/ /_/\____/_/ /_/ 
                                         /____/                        
    Zero-DPI Obfuscated UDP Tunnel Proxy (WireGuard 127.0.0.1:51821)
""")
    print(f"{Colors.RESET}")

# --- Cryptographic Helpers ---
def compute_key_id(token: str) -> tuple[bytes, str]:
    """Computes 8-byte raw KeyID and 16-character hex KeyID from secret token."""
    h = hashlib.sha256(token.encode('utf-8')).digest()
    raw_kid = h[:8]
    kid_hex = raw_kid.hex()
    return raw_kid, kid_hex

def derive_keys(token: str, kid_hex: str):
    """
    Derives master_key via PBKDF2-HMAC-SHA256,
    then expands mask_key and payload_key via HKDF-SHA256.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    master_key = hashlib.pbkdf2_hmac(
        'sha256',
        token.encode('utf-8'),
        kid_hex.encode('utf-8'),
        PBKDF2_ITERATIONS,
        dklen=32
    )

    # Derive mask_key (info: "aegis-v2-header-mask")
    hkdf_mask = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"aegis-v2-salt",
        info=b"aegis-v2-header-mask"
    )
    mask_key = hkdf_mask.derive(master_key)

    # Derive payload_key (info: "aegis-v2-payload-key")
    hkdf_payload = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"aegis-v2-salt",
        info=b"aegis-v2-payload-key"
    )
    payload_key = hkdf_payload.derive(master_key)

    return master_key, mask_key, payload_key

def mask_unmask_header(data: bytes, mask_key: bytes, hdr_iv: bytes) -> bytes:
    """ChaCha20 stream cipher masking for the 16-byte header."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    full_nonce = b"\x00\x00\x00\x00" + hdr_iv
    cipher = Cipher(algorithms.ChaCha20(mask_key, full_nonce), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data)

def find_native_binary() -> Path | None:
    """Searches for native compiled aegs-client binary."""
    script_dir = Path(__file__).resolve().parent
    root_dir = script_dir.parent

    candidates = [
        script_dir / "aegs-client",
        script_dir / "aegs-client.exe",
        script_dir / "client",
        root_dir / "aegs-client",
        root_dir / "aegs-client.exe",
        root_dir / "client",
        root_dir / "aegis_client",
        root_dir / "aegis_client.exe",
        Path("/usr/local/bin/aegs-client"),
        Path("/usr/local/bin/aegis_client"),
    ]

    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c

    # Search in PATH
    for name in ["aegs-client", "aegis_client", "aegs-client.exe", "aegis_client.exe"]:
        p = shutil_which(name)
        if p:
            return Path(p)

    return None

def shutil_which(cmd: str) -> str | None:
    import shutil
    return shutil.which(cmd)

# --- Pure-Python Proxy Engine ---
def run_python_proxy(server_host: str, token: str, local_port: int = DEFAULT_LOCAL_PORT):
    """
    Pure Python zero-dependency (cryptography required) AEGS v2 proxy client.
    Listens on 127.0.0.1:local_port, forwards encrypted UDP datagrams to server_host:50001.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except ImportError:
        print(f"{Colors.RED}[!] 'cryptography' library is required for pure-Python mode.{Colors.RESET}")
        print(f"    Install it with: {Colors.CYAN}pip install cryptography{Colors.RESET}")
        sys.exit(1)

    raw_kid, kid_hex = compute_key_id(token)
    master_key, mask_key, payload_key = derive_keys(token, kid_hex)
    aead = ChaCha20Poly1305(payload_key)

    # Resolve server address
    try:
        server_ip = socket.gethostbyname(server_host)
    except socket.gaierror as e:
        print(f"{Colors.RED}[!] Failed to resolve server '{server_host}': {e}{Colors.RESET}")
        sys.exit(1)

    server_addr = (server_ip, DEFAULT_SERVER_PORT)

    # Bind local UDP listener for WireGuard
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    sock.bind(("127.0.0.1", local_port))
    sock.setblocking(False)

    print(f"{Colors.GREEN}[OK] Python AEGS v2 Proxy Listener Active on 127.0.0.1:{local_port}{Colors.RESET}")
    print(f"     - Remote Server: {server_host} ({server_ip}:{DEFAULT_SERVER_PORT})")
    print(f"     - Key ID:        {kid_hex}")
    print(f"     - WireGuard:     Set Endpoint = 127.0.0.1:{local_port}\n")
    print(f"{Colors.YELLOW}Proxying packets with Zero-DPI protection (Press Ctrl+C to stop)...{Colors.RESET}")

    wg_client_addr = None
    client_tx_seq = 0
    replay_last_seq = 0
    replay_bitmap = 0

    def check_replay(seq: int) -> bool:
        nonlocal replay_last_seq, replay_bitmap
        if seq == 0:
            return True
        if seq > replay_last_seq:
            diff = seq - replay_last_seq
            if diff < 64:
                replay_bitmap = ((replay_bitmap << diff) | 1) & 0xFFFFFFFFFFFFFFFF
            else:
                replay_bitmap = 1
            replay_last_seq = seq
            return False
        diff = replay_last_seq - seq
        if diff >= 64:
            return True
        if replay_bitmap & (1 << diff):
            return True
        replay_bitmap |= (1 << diff)
        return False

    try:
        while True:
            r, _, _ = select.select([sock], [], [], 1.0)
            if not r:
                continue

            data, addr = sock.recvfrom(BUFFER_SIZE)
            if not data:
                continue

            if addr == server_addr:
                # Inbound packet from remote AEGS server -> decrypt -> send to local WireGuard
                if len(data) < 56:
                    continue

                hdr_iv = data[:12]
                masked_hdr = data[12:28]
                unmasked_hdr = mask_unmask_header(masked_hdr, mask_key, hdr_iv)

                # Verify KeyID and VerMagic
                if unmasked_hdr[:8] != raw_kid or unmasked_hdr[12:16] != VER_MAGIC:
                    continue

                junk_len = struct.unpack(">H", unmasked_hdr[8:10])[0]
                aead_offset = 12 + 16 + junk_len
                if len(data) < aead_offset + 12 + TAG_LEN:
                    continue

                aead_nonce = data[aead_offset : aead_offset + 12]
                rx_seq = struct.unpack("<Q", aead_nonce[:8])[0]
                if check_replay(rx_seq):
                    continue

                ct = data[aead_offset + 12 :]
                try:
                    pt = aead.decrypt(aead_nonce, ct, None)
                except Exception:
                    continue

                if len(pt) < 2:
                    continue

                plen = struct.unpack(">H", pt[:2])[0]
                if wg_client_addr and plen <= len(pt) - 2:
                    sock.sendto(pt[2 : 2 + plen], wg_client_addr)

            else:
                # Outbound packet from local WireGuard -> encrypt & pad -> send to server
                wg_client_addr = addr

                pad_len = PAD_MIN + (secrets.randbelow(PAD_MAX - PAD_MIN + 1))
                plen = len(data)
                frame = struct.pack(">H", plen) + data + secrets.token_bytes(pad_len)

                client_tx_seq += 1
                aead_nonce = struct.pack("<Q", client_tx_seq) + secrets.token_bytes(4)
                ct = aead.encrypt(aead_nonce, frame, None)

                # 20% chance of junk insertion
                junk_len = 16 + secrets.randbelow(49) if secrets.randbelow(100) < 20 else 0

                hdr_plain = raw_kid + struct.pack(">H", junk_len) + b"\x00\x00" + VER_MAGIC
                hdr_iv = secrets.token_bytes(12)
                masked_hdr = mask_unmask_header(hdr_plain, mask_key, hdr_iv)

                out_pkt = bytearray()
                out_pkt.extend(hdr_iv)
                out_pkt.extend(masked_hdr)
                if junk_len > 0:
                    out_pkt.extend(secrets.token_bytes(junk_len))
                out_pkt.extend(aead_nonce)
                out_pkt.extend(ct)

                sock.sendto(bytes(out_pkt), server_addr)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Stopping AEGS client proxy...{Colors.RESET}")
    finally:
        sock.close()

# --- Config & CLI Handlers ---
def generate_wg_config(local_port: int, output_file: str = "aegis-wg.conf"):
    content = f"""# ==============================================================================
# WireGuard Client Configuration with AEGS v2 Zero-DPI Obfuscator
# ==============================================================================
[Interface]
# Replace with your assigned WireGuard Client Private Key and Address:
PrivateKey = YOUR_CLIENT_PRIVATE_KEY_HERE
Address = 10.8.0.2/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
# Replace with your server's WireGuard Public Key:
PublicKey = YOUR_SERVER_WIREGUARD_PUBLIC_KEY_HERE
# CRITICAL: Point Endpoint to local AEGS proxy port!
Endpoint = 127.0.0.1:{local_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    Path(output_file).write_text(content, encoding='utf-8')
    print(f"{Colors.GREEN}[OK] WireGuard configuration template saved -> {output_file}{Colors.RESET}")

def run_command(args):
    banner()
    server = args.server
    token = args.token
    port = args.port

    if not server or not token:
        print(f"{Colors.RED}[!] Server address and secret token are required.{Colors.RESET}")
        print(f"    Usage: python quick_client.py run --server <HOST> --token <TOKEN>")
        sys.exit(1)

    native_bin = find_native_binary()
    if native_bin and not args.force_python:
        print(f"{Colors.GREEN}[OK] Using native compiled binary: {native_bin}{Colors.RESET}")
        cmd = [str(native_bin), "--server", server, "--token", token, "--port", str(port)]
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            pass
    else:
        if args.force_python:
            print(f"{Colors.CYAN}[*] Running with pure-Python proxy engine (--force-python requested)...{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[*] Native binary not found. Falling back to built-in pure-Python engine...{Colors.RESET}")
        run_python_proxy(server, token, port)

def keyid_command(args):
    _, kid_hex = compute_key_id(args.token)
    print(f"\n{Colors.BOLD}Secret Token:{Colors.RESET} {args.token}")
    print(f"{Colors.CYAN}{Colors.BOLD}Key ID (Hex):{Colors.RESET} {kid_hex}\n")

def interactive_wizard():
    banner()
    print(f"{Colors.WHITE}{Colors.BOLD}AEGS v2 Client Setup Wizard{Colors.RESET}\n")

    server = input("Enter Server IP or Hostname: ").strip()
    token = input("Enter Secret Token: ").strip()
    port_input = input(f"Enter Local UDP Port [{DEFAULT_LOCAL_PORT}]: ").strip()
    port = int(port_input) if port_input else DEFAULT_LOCAL_PORT

    if not server or not token:
        print(f"{Colors.RED}[!] Server and token are required.{Colors.RESET}")
        return

    generate_wg_config(port)
    print("")
    native_bin = find_native_binary()
    if native_bin:
        print(f"{Colors.GREEN}[OK] Found native binary: {native_bin}{Colors.RESET}")
        try:
            subprocess.run([str(native_bin), "--server", server, "--token", token, "--port", str(port)])
        except KeyboardInterrupt:
            pass
    else:
        run_python_proxy(server, token, port)

def main():
    parser = argparse.ArgumentParser(description="AEGS v2 Client Management & Proxy CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Run command
    run_parser = subparsers.add_parser("run", help="Launch AEGS obfuscator client proxy")
    run_parser.add_argument("-s", "--server", help="AEGS server IP or domain")
    run_parser.add_argument("-t", "--token", help="User authentication secret token")
    run_parser.add_argument("-p", "--port", type=int, default=DEFAULT_LOCAL_PORT, help="Local UDP port (default: 51821)")
    run_parser.add_argument("--force-python", action="store_true", help="Force pure-Python proxy instead of native binary")

    # KeyID command
    kid_parser = subparsers.add_parser("keyid", help="Calculate KeyID for a given token")
    kid_parser.add_argument("-t", "--token", required=True, help="Secret token")

    # Config command
    cfg_parser = subparsers.add_parser("gen-wg", help="Generate sample WireGuard client config")
    cfg_parser.add_argument("-p", "--port", type=int, default=DEFAULT_LOCAL_PORT, help="Local port")
    cfg_parser.add_argument("-o", "--out", default="aegis-wg.conf", help="Output file path")

    # Interactive wizard
    subparsers.add_parser("wizard", help="Interactive setup wizard")

    args = parser.parse_args()

    if args.command == "run":
        run_command(args)
    elif args.command == "keyid":
        keyid_command(args)
    elif args.command == "gen-wg":
        generate_wg_config(args.port, args.out)
    elif args.command == "wizard" or args.command is None:
        interactive_wizard()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
