#!/usr/bin/env python3
"""Leader-aware test gateway for the Compose performance topology.

Mutating requests are sent to the node whose `/health` reports `leader`; reads
round-robin across healthy nodes. This is test infrastructure, not a production
load-balancer implementation.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


UPSTREAM_SERVICE = os.environ.get("CHANCELA_PERF_UPSTREAM", "chancela-cluster")
UPSTREAM_PORT = int(os.environ.get("CHANCELA_PERF_UPSTREAM_PORT", "8080"))
LISTEN_HOST = os.environ.get("CHANCELA_PERF_GATEWAY_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("CHANCELA_PERF_GATEWAY_PORT", "8081"))
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class Topology:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.cached_at = 0.0
        self.nodes: list[str] = []
        self.leader: str | None = None
        self.read_index = 0

    def refresh(self) -> None:
        addresses = sorted(
            {
                item[4][0]
                for item in socket.getaddrinfo(
                    UPSTREAM_SERVICE,
                    UPSTREAM_PORT,
                    type=socket.SOCK_STREAM,
                )
            }
        )
        healthy: list[str] = []
        leader = None
        for address in addresses:
            try:
                connection = http.client.HTTPConnection(address, UPSTREAM_PORT, timeout=2)
                connection.request("GET", "/health")
                response = connection.getresponse()
                body = response.read()
                connection.close()
                if response.status != 200:
                    continue
                health = json.loads(body)
                healthy.append(address)
                if health.get("cluster", {}).get("role") == "leader":
                    leader = address
            except Exception:
                continue
        self.nodes = healthy
        self.leader = leader
        self.cached_at = time.monotonic()

    def choose(self, mutating: bool) -> str | None:
        with self.lock:
            if time.monotonic() - self.cached_at > 0.5 or not self.nodes:
                self.refresh()
            if mutating:
                return self.leader
            if not self.nodes:
                return None
            selected = self.nodes[self.read_index % len(self.nodes)]
            self.read_index += 1
            return selected


TOPOLOGY = Topology()


class GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "chancela-perf-gateway/1"

    def do_GET(self) -> None:
        self.proxy()

    def do_HEAD(self) -> None:
        self.proxy()

    def do_POST(self) -> None:
        self.proxy()

    def do_PUT(self) -> None:
        self.proxy()

    def do_PATCH(self) -> None:
        self.proxy()

    def do_DELETE(self) -> None:
        self.proxy()

    def proxy(self) -> None:
        upstream = TOPOLOGY.choose(self.command in MUTATING)
        if upstream is None:
            self.send_json(
                503,
                {
                    "error": "performance gateway has no eligible upstream",
                    "mutating": self.command in MUTATING,
                },
            )
            return
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length) if length else None
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP and key.lower() != "host"
        }
        peer = self.client_address[0]
        prior = self.headers.get("x-forwarded-for")
        headers["x-forwarded-for"] = f"{prior}, {peer}" if prior else peer
        headers["x-forwarded-proto"] = "http"
        headers["host"] = f"{UPSTREAM_SERVICE}:{UPSTREAM_PORT}"
        try:
            connection = http.client.HTTPConnection(upstream, UPSTREAM_PORT, timeout=120)
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in HOP_BY_HOP and key.lower() != "content-length":
                    self.send_header(key, value)
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
            connection.close()
        except Exception as error:
            with TOPOLOGY.lock:
                TOPOLOGY.cached_at = 0
            self.send_json(
                502,
                {"error": f"performance gateway upstream failure: {type(error).__name__}"},
            )

    def send_json(self, status: int, value: dict) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        print(
            json.dumps(
                {
                    "at": time.time(),
                    "client": self.client_address[0],
                    "message": fmt % args,
                },
                separators=(",", ":"),
            ),
            flush=True,
        )


if __name__ == "__main__":
    print(
        f"performance gateway listening on {LISTEN_HOST}:{LISTEN_PORT}, "
        f"upstream={UPSTREAM_SERVICE}:{UPSTREAM_PORT}",
        flush=True,
    )
    ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), GatewayHandler).serve_forever()
