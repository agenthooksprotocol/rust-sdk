#!/usr/bin/env python3
"""Minimal executable stdio policy for registered_hooks.rs; stdout is JSON-RPC only."""
import json
import sys

for line in sys.stdin:
    request = json.loads(line)
    event = request["params"]["event"]
    if "id" not in request:
        print("observed " + event["type"], file=sys.stderr, flush=True)
        continue
    effects = [{"type": "allow"}]
    if event["tool"]["input"]["command"] != "echo hello":
        effects = [{"type": "deny", "reason": "Only the demo command is allowed"}]
    print(json.dumps({
        "jsonrpc": "2.0", "id": request["id"],
        "result": {"protocolVersion": "draft", "effects": effects},
    }), flush=True)
