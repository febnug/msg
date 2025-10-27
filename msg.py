#!/usr/bin/env python3
"""
Detect mail server software for a domain with additions:
 - reverse DNS / PTR lookup of SMTP peer IP
 - optional VRFY/EXPN probing (disabled by default; use --enable-vrfy)

Usage:
  python3 msg.py example.tld --starttls --probe-imap-pop
  python3 msg.py example.tld --enable-vrfy

WARNING:
 - VRFY/EXPN can be considered intrusive by some providers. Use on domains you own/are authorized to test.
"""
import dns.resolver
import socket
import ssl
import argparse
import re
import json
from typing import List, Tuple

TIMEOUT = 6.0
SMTP_PORTS = [25]
IMAP_PORTS = [(993, True), (143, False)]
POP3_PORTS = [(995, True), (110, False)]

KNOWN_SIGNATURES = {
    'Postfix': re.compile(r'Postfix', re.I),
    'Exim': re.compile(r'Exim', re.I),
    'Sendmail': re.compile(r'Sendmail', re.I),
    'Microsoft Exchange': re.compile(r'Microsoft|Exchange', re.I),
    'OpenSMTPD': re.compile(r'OpenSMTPD', re.I),
    'qmail': re.compile(r'qmail', re.I),
    'Courier': re.compile(r'Courier', re.I),
    'Dovecot': re.compile(r'Dovecot', re.I),
    'Cyrus': re.compile(r'Cyrus', re.I),
    'MailEnable': re.compile(r'MailEnable', re.I),
    'iRedMail': re.compile(r'iRedMail', re.I),
    'Zimbra': re.compile(r'Zimbra', re.I),
    'Haraka': re.compile(r'Haraka', re.I),
    'Open-Xchange': re.compile(r'OpenXchange|Open-Xchange', re.I),
}

def resolve_mx(domain: str) -> List[Tuple[int, str]]:
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        mx = []
        for r in answers:
            mx.append((int(r.preference), str(r.exchange).rstrip('.')))
        mx.sort()
        return mx
    except Exception:
        return []

def try_recv(sock: socket.socket, size=4096) -> bytes:
    try:
        return sock.recv(size)
    except Exception:
        return b''

def parse_server_signatures(text: str):
    found = []
    for name, pattern in KNOWN_SIGNATURES.items():
        if pattern.search(text):
            found.append(name)
    return found

def reverse_dns_of_peer(sock: socket.socket):
    """
    Given a connected socket, determine remote IP and do reverse DNS (PTR).
    Returns (ip, ptr_hostname_or_None, error_or_None)
    """
    try:
        peer = sock.getpeername()
        remote_ip = peer[0]
        try:
            ptr = socket.gethostbyaddr(remote_ip)[0]
        except Exception as e:
            ptr = None
        return remote_ip, ptr, None
    except Exception as e:
        return None, None, str(e)

def send_cmd_and_collect(sock, cmd: bytes, multiline_terminator=b'\r\n', read_until_pattern=None):
    """
    send command (bytes) and try to read response (basic).
    returns bytes response (may be partial)
    """
    try:
        sock.sendall(cmd)
    except Exception:
        return b''
    resp = b''
    try:
        while True:
            part = try_recv(sock, 4096)
            if not part:
                break
            resp += part
            # quick heuristic: stop if we see newline followed by 3-digit + space (non-cont)
            if re.search(rb'\r\n\d{3}\s', resp):
                break
            # keep a finite loop guard - if it's huge, break
            if len(resp) > 65536:
                break
    except Exception:
        pass
    return resp

def probe_smtp(host: str, port: int = 25, starttls=False, enable_vrfy=False) -> dict:
    info = {
        'host': host,
        'port': port,
        'banner': None,
        'ehlo': None,
        'signatures': [],
        'tls_cert_subject': None,
        'ptr_ip': None,
        'ptr_name': None,
        'vrfy': None,
        'expn': None,
        'error': None,
    }
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        try:
            banner = try_recv(sock, 4096).decode(errors='ignore').strip()
        except Exception:
            banner = None
        info['banner'] = banner
        # reverse DNS of peer IP
        ip, ptr, err = reverse_dns_of_peer(sock)
        info['ptr_ip'] = ip
        info['ptr_name'] = ptr
        if err:
            info.setdefault('notes', []).append(f'PTR error: {err}')

        # send EHLO
        resp = send_cmd_and_collect(sock, b'EHLO example.com\r\n')
        info['ehlo'] = resp.decode(errors='ignore').strip()
        # parse signatures
        combined = (info['banner'] or '') + '\n' + (info['ehlo'] or '')
        info['signatures'] = sorted(set(parse_server_signatures(combined)))

        # VRFY/EXPN if asked (risky; may be rejected)
        if enable_vrfy:
            try:
                vr = send_cmd_and_collect(sock, b'VRFY postmaster\r\n')
                info['vrfy'] = vr.decode(errors='ignore').strip()
            except Exception as e:
                info['vrfy'] = f'error: {e}'
            try:
                ex = send_cmd_and_collect(sock, b'EXPN postmaster\r\n')
                info['expn'] = ex.decode(errors='ignore').strip()
            except Exception as e:
                info['expn'] = f'error: {e}'

        # STARTTLS handling
        if starttls and b'STARTTLS' in (resp or b'').upper():
            try:
                ready = send_cmd_and_collect(sock, b'STARTTLS\r\n')
                if ready and ready.strip().startswith(b'220'):
                    context = ssl.create_default_context()
                    tls = context.wrap_socket(sock, server_hostname=host)
                    cert = tls.getpeercert()
                    subj = None
                    if cert:
                        # extract subject CN / subject for readability
                        try:
                            subj = " ".join("=".join(x) for r in cert.get('subject', []) for x in r)
                        except Exception:
                            subj = str(cert)
                    info['tls_cert_subject'] = subj
                    # after TLS, try EHLO again
                    try:
                        resp2 = send_cmd_and_collect(tls, b'EHLO example.com\r\n')
                        info['ehlo_after_tls'] = resp2.decode(errors='ignore').strip()
                        info['signatures'] = sorted(set(info['signatures'] + parse_server_signatures(info['ehlo_after_tls'] + (info['banner'] or ''))))
                    except Exception:
                        pass
                    try:
                        tls.close()
                    except Exception:
                        pass
                else:
                    info.setdefault('notes', []).append('STARTTLS not accepted')
            except Exception as e:
                info.setdefault('notes', []).append(f'STARTTLS failed: {e}')

        try:
            sock.sendall(b'QUIT\r\n')
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
    except Exception as e:
        info['error'] = str(e)
        if sock:
            try: sock.close()
            except: pass
    return info

def probe_imap_pop_guess(domain: str) -> List[dict]:
    guesses = []
    hosts = [f'mail.{domain}', f'imap.{domain}', f'webmail.{domain}']
    for h in hosts:
        for port, is_ssl in IMAP_PORTS:
            try:
                if is_ssl:
                    ctx = ssl.create_default_context()
                    s = ctx.wrap_socket(socket.socket(), server_hostname=h)
                    s.settimeout(TIMEOUT)
                    s.connect((h, port))
                else:
                    s = socket.create_connection((h, port), timeout=TIMEOUT)
                banner = try_recv(s, 2048).decode(errors='ignore').strip()
                signatures = parse_server_signatures(banner or '')
                guesses.append({'host': h, 'service': 'IMAP', 'port': port, 'banner': banner, 'signatures': signatures})
                try: s.close()
                except: pass
            except Exception:
                pass
        for port, is_ssl in POP3_PORTS:
            try:
                if is_ssl:
                    ctx = ssl.create_default_context()
                    s = ctx.wrap_socket(socket.socket(), server_hostname=h)
                    s.settimeout(TIMEOUT)
                    s.connect((h, port))
                else:
                    s = socket.create_connection((h, port), timeout=TIMEOUT)
                banner = try_recv(s, 2048).decode(errors='ignore').strip()
                signatures = parse_server_signatures(banner or '')
                guesses.append({'host': h, 'service': 'POP3', 'port': port, 'banner': banner, 'signatures': signatures})
                try: s.close()
                except: pass
            except Exception:
                pass
    return guesses

def detect(domain: str, starttls=False, probe_imap_pop=False, enable_vrfy=False):
    report = {'domain': domain, 'mx': [], 'smtp_probes': [], 'imap_pop_guesses': []}
    mx = resolve_mx(domain)
    report['mx'] = [{'preference': p, 'host': h} for p, h in mx] or []
    if not mx:
        report['mx'] = [{'preference': 0, 'host': domain}]
        mx = [(0, domain)]
    for pref, host in mx:
        for port in SMTP_PORTS:
            info = probe_smtp(host, port=port, starttls=starttls, enable_vrfy=enable_vrfy)
            report['smtp_probes'].append({'mx': host, 'probe': info})
    if probe_imap_pop:
        report['imap_pop_guesses'] = probe_imap_pop_guess(domain)
    # best guess aggregation
    sigs = {}
    for p in report['smtp_probes']:
        s = p['probe'].get('signatures') or []
        for name in s:
            sigs[name] = sigs.get(name, 0) + 1
    for p in report.get('imap_pop_guesses', []):
        for name in p.get('signatures', []):
            sigs[name] = sigs.get(name, 0) + 1
    report['guesses'] = sorted([(k, v) for k, v in sigs.items()], key=lambda x: -x[1])
    return report

def pretty_print(report, as_json=False):
    if as_json:
        print(json.dumps(report, indent=2))
        return
    print(f"Domain: {report['domain']}")
    print("MX records:")
    for m in report['mx']:
        print(f"  - {m['preference']} {m['host']}")
    print("\nSMTP probes:")
    for p in report['smtp_probes']:
        info = p['probe']
        print(f"  * MX host: {p['mx']} port {info['port']}")
        if info.get('error'):
            print(f"    - ERROR: {info['error']}")
            continue
        if info.get('banner'):
            print(f"    - Banner: {info['banner'].splitlines()[0]}")
        if info.get('ptr_ip'):
            print(f"    - Peer IP: {info['ptr_ip']}")
        if info.get('ptr_name'):
            print(f"    - PTR(hostname): {info['ptr_name']}")
        if info.get('ehlo'):
            eh = info['ehlo'].splitlines()
            lines = eh[:6]
            for ln in lines:
                print(f"      {ln}")
        if info.get('signatures'):
            print(f"    - Detected signatures: {', '.join(info['signatures'])}")
        if info.get('tls_cert_subject'):
            print(f"    - STARTTLS cert subject: {info['tls_cert_subject']}")
        if info.get('vrfy') is not None:
            print(f"    - VRFY result: {info['vrfy'].splitlines()[0] if info['vrfy'] else '(no response)'}")
        if info.get('expn') is not None:
            print(f"    - EXPN result: {info['expn'].splitlines()[0] if info['expn'] else '(no response)'}")
        if info.get('notes'):
            for n in info['notes']:
                print(f"    - note: {n}")
    if report.get('imap_pop_guesses'):
        print("\nIMAP/POP guesses (common hosts):")
        for g in report['imap_pop_guesses']:
            print(f"  - {g['service']} {g['host']}:{g['port']} -> banner: {g['banner'].splitlines()[0] if g.get('banner') else 'no response'} sigs: {g.get('signatures')}")
    print("\nBest signature guesses (by frequency):")
    if report.get('guesses'):
        for name, cnt in report['guesses']:
            print(f"  - {name} (score {cnt})")
    else:
        print("  - (no signatures detected)")

def main():
    p = argparse.ArgumentParser(description="Detect mail server software for a domain (with PTR and optional VRFY/EXPN).")
    p.add_argument("domain", help="Domain to inspect (e.g. pantero.id)")
    p.add_argument("--starttls", action="store_true", help="Attempt STARTTLS on SMTP to inspect TLS cert")
    p.add_argument("--probe-imap-pop", action="store_true", help="Also probe common IMAP/POP hosts like mail., imap., webmail.")
    p.add_argument("--enable-vrfy", action="store_true", help="Enable VRFY/EXPN probing (may be blocked/considered intrusive)")
    p.add_argument("--json", action="store_true", help="Output JSON")
    args = p.parse_args()
    report = detect(args.domain, starttls=args.starttls, probe_imap_pop=args.probe_imap_pop, enable_vrfy=args.enable_vrfy)
    pretty_print(report, as_json=args.json)

if __name__ == "__main__":
    main()
