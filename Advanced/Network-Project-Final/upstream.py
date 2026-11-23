"""Assignment UDP text upstream simulator; run before dns_proxy.py."""
import socket
from pathlib import Path


def config():
    result = {}
    for line in (Path(__file__).resolve().parent / 'config.txt').read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            result[k.strip()] = v.strip()
    return result


def main():
    c = config()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((c['upstream_ip'], int(c['upstream_port'])))
        print('Upstream Simulator is running...', flush=True)
        n = 0
        while True:
            data, addr = server.recvfrom(4096)
            parts = data.decode('utf-8', errors='replace').strip().split()
            name = parts[1].lower() if len(parts) == 2 and parts[0] == 'QUERY' else '(invalid)'
            if name in {'missing.example.net', 'readiness-check.invalid'}:
                answer = 'NOT_FOUND'
            elif name == 'example.com':
                answer = 'OK 93.184.216.34 60'
            elif name.startswith('site') and name.endswith('.example.net'):
                answer = 'OK 198.51.100.7 30'
            else:
                answer = 'OK 198.51.100.7 5'
            n += 1
            print(f'Request #{n}: {name} -> {answer}', flush=True)
            server.sendto(answer.encode('ascii'), addr)


if __name__ == '__main__':
    main()
