#!/usr/bin/env python3
"""Local-only HTTP policy fixture; set REGISTERED_HOOK_TOKEN in both processes."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = os.environ["REGISTERED_HOOK_TOKEN"]


class Policy(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/hooks":
            self.send_error(404)
            return
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            self.send_error(401)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 1024 * 1024:
            self.send_error(413)
            return
        request = json.loads(self.rfile.read(length))
        event = request["params"]["event"]
        if "id" not in request:
            print("observed " + event["type"], file=sys.stderr, flush=True)
            self.send_response(204)
            self.end_headers()
            return
        effects = [{"type": "allow"}]
        if event["tool"]["input"]["command"] != "echo hello":
            effects = [{"type": "deny", "reason": "Only the demo command is allowed"}]
        body = json.dumps({
            "jsonrpc": "2.0", "id": request["id"],
            "result": {"protocolVersion": "draft", "effects": effects},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HTTPServer(("127.0.0.1", 8765), Policy).serve_forever()
