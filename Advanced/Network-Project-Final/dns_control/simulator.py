"""Controllable local UDP upstream simulator used by the dashboard."""
from __future__ import annotations

import ipaddress
import socketserver
import threading


class _SimulatorHandler(socketserver.BaseRequestHandler):
    def handle(self):
        payload, udp_socket = self.request
        reply = self.server.handle_query(payload)
        udp_socket.sendto(reply.encode("ascii"), self.client_address)


class _SimulatorUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, address):
        super().__init__(address, _SimulatorHandler)
        self.request_count = 0
        self.last_request = None
        self.metrics_lock = threading.Lock()

    def handle_query(self, payload: bytes) -> str:
        fields = payload.decode("ascii", errors="replace").strip().split(maxsplit=1)
        if len(fields) == 2 and fields[0] == "QUERY":
            domain = fields[1].strip().lower().rstrip(".")
        else:
            domain = "(invalid)"

        # Flexible demo behavior: any valid-looking domain resolves, except the
        # explicit missing fixture retained by acceptance scenarios T10a/T10b.
        if domain in {"missing.example.net", "readiness-check.invalid"}:
            reply = "NOT_FOUND"
        elif domain == "example.com":
            reply = "OK 93.184.216.34 60"
        elif domain.startswith("site") and domain.endswith(".example.net"):
            reply = "OK 198.51.100.7 30"
        else:
            reply = "OK 198.51.100.7 5"

        with self.metrics_lock:
            self.request_count += 1
            self.last_request = {"domain": domain, "reply": reply}
            number = self.request_count
        print(f"[Dashboard Simulator] Request #{number}: {domain} -> {reply}", flush=True)
        return reply


class LocalSimulatorController:
    """Owns the dashboard's optional in-process UDP simulator."""

    def __init__(self):
        self._lock = threading.RLock()
        self._server = None
        self._thread = None
        self._address = None
        self._last_error = None

    @staticmethod
    def eligible(cfg) -> bool:
        if str(cfg.get("real_dns_enabled", "false")).lower() == "true":
            return False
        try:
            return ipaddress.IPv4Address(cfg["upstream_ip"]).is_loopback
        except (KeyError, ValueError):
            return False

    def start(self, cfg):
        if not self.eligible(cfg):
            raise ValueError("Local simulator requires simulated DNS mode and a loopback upstream IP.")

        address = (cfg["upstream_ip"], int(cfg["upstream_port"]))
        with self._lock:
            if self._server is not None:
                if self._address == address:
                    return self.snapshot(cfg)
                self._stop_locked()

            try:
                server = _SimulatorUDPServer(address)
            except OSError as exc:
                self._last_error = str(exc)
                raise
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.1},
                name="dns-dashboard-simulator",
                daemon=True,
            )
            thread.start()
            self._server = server
            self._thread = thread
            self._address = address
            self._last_error = None
            return self.snapshot(cfg)

    def start_if_available(self, cfg):
        if not self.eligible(cfg):
            return self.snapshot(cfg)
        try:
            return self.start(cfg)
        except OSError as exc:
            with self._lock:
                self._last_error = str(exc)
            return self.snapshot(cfg)

    def _stop_locked(self):
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        self._address = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None and thread.is_alive():
            thread.join(timeout=2)

    def stop(self):
        with self._lock:
            self._stop_locked()
            self._last_error = None
            return {"running": False}

    def reconcile(self, cfg):
        """Stop a running simulator if its configured endpoint is no longer valid."""
        with self._lock:
            if self._server is None:
                return
            expected = (cfg.get("upstream_ip"), int(cfg.get("upstream_port", 0)))
            if not self.eligible(cfg) or expected != self._address:
                self._stop_locked()

    def snapshot(self, cfg):
        with self._lock:
            eligible = self.eligible(cfg)
            server = self._server
            if server is not None:
                with server.metrics_lock:
                    requests = server.request_count
                    last_request = dict(server.last_request) if server.last_request else None
                status = "running"
                address = self._address
            else:
                requests = 0
                last_request = None
                address = (cfg.get("upstream_ip"), cfg.get("upstream_port")) if eligible else None
                status = "port_in_use" if self._last_error else ("stopped" if eligible else "unavailable")
            return {
                "available": eligible,
                "running": server is not None,
                "status": status,
                "address": f"{address[0]}:{address[1]}" if address else None,
                "requests": requests,
                "last_request": last_request,
                "message": self._last_error,
            }
