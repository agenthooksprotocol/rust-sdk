#!/usr/bin/env python3
"""Regression tests: transport outages never satisfy expectError; redirects never follow."""
import importlib.util
import json
import os
import select
import time
import urllib.error
import urllib.request
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SDK = Path(__file__).resolve().parents[1]
SHARED = SDK.parent / 'agent-hooks-protocol/interop'
spec = importlib.util.spec_from_file_location('scenarios', SHARED / 'generate_scenarios.py')
scenarios = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scenarios)
CAPS = scenarios.CAPS
BINARY = str(SDK / 'target/debug/interop')


def reject_bad_http_bodies(root, scenario, case):
    ready = root / 'ready.json'
    config = root / 'server.json'
    config.write_text(json.dumps(dict(transport='http', scenarioFile=str(scenario),
                                     readinessFile=str(ready), auth={'mode':'none'})))
    for kind in ['interop', 'compaction']:
        command = [BINARY, 'server', '--config', str(config)] if kind == 'interop' else [
            str(SDK / 'target/debug/compaction'), 'server']
        process = subprocess.Popen(command, cwd=SDK, stdout=subprocess.PIPE,
                                   env={**os.environ, 'AHP_COMPACTION_TOKEN':'TEST-ONLY-token'})
        try:
            if kind == 'interop':
                deadline = time.monotonic() + 15
                while not ready.exists():
                    assert process.poll() is None, 'server exited before readiness'
                    if time.monotonic() >= deadline: raise TimeoutError('readiness')
                    time.sleep(.02)
                endpoint = json.loads(ready.read_text())['endpoint']
                valid = case['request']
            else:
                assert select.select([process.stdout], [], [], 15)[0], 'readiness timeout'
                endpoint = json.loads(process.stdout.readline())['endpoint']
                valid = dict(jsonrpc='2.0', id='survival', method='compaction/run',
                             params={'instructions':'summarize'})
            malformed = [b'\xff', b'{']
            if kind == 'compaction': malformed.append(b' ' * (4 * 1024 * 1024 + 1))
            for body in malformed:
                request = urllib.request.Request(endpoint, data=body,
                    headers={'Authorization':'Bearer TEST-ONLY-token'})
                try:
                    urllib.request.urlopen(request, timeout=5).close()
                    raise AssertionError('malformed body accepted')
                except urllib.error.HTTPError as error:
                    assert error.code == (413 if len(body) > 4 * 1024 * 1024 else 400)
                    error.close()
                # Rejection is isolated to one request, not termination of the listener.
                request = urllib.request.Request(endpoint, data=json.dumps(valid).encode(),
                    headers={'Authorization':'Bearer TEST-ONLY-token'})
                with urllib.request.urlopen(request, timeout=5) as response:
                    reply = json.load(response)
                    assert response.status == 200 and reply['id'] == valid['id']
                    if kind == 'compaction': assert 'result' in reply, reply
                assert process.poll() is None
            print(f'{kind}-malformed-http-survival: passed')
        finally:
            process.kill()
            process.wait(timeout=5)
            process.stdout.close()


def main():
    case = next(s for s in scenarios.build()['scenarios'] if s.get('expectError'))
    redirected = []
    release = threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def send_json(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def do_GET(self):
            if self.path == '/capabilities': self.send_json(200, CAPS)
            else: redirected.append(self.path); self.send_json(200, CAPS)
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', 0)))
            if self.path == '/redirected':
                redirected.append(self.path)
                self.send_json(200, case['response'])
            elif self.path == '/token' or self.server.mode == 'redirect':
                self.send_response(307)
                self.send_header('Location', '/redirected')
                self.send_header('Content-Length', '0')
                self.end_headers()
            elif self.server.mode == '503': self.send_json(503, case['response'])
            elif self.server.mode == 'reset':
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            elif self.server.mode == 'watchdog': release.wait(20)
            else: self.send_json(200, case['response'])
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rust-transport-') as temp:
            root = Path(temp)
            scenario = root / 'scenarios.json'
            scenario.write_text(json.dumps({'version':1,'scenarios':[case]}))
            reject_bad_http_bodies(root, scenario, case)
            endpoint = f'http://127.0.0.1:{server.server_port}'
            def run(label, extra, passed=False, require_report=True):
                report = root / 'report.json'
                report.unlink(missing_ok=True)
                config = dict(transport='http', endpoint=endpoint, scenarioFile=str(scenario), reportFile=str(report), auth={'mode':'none'}, **extra)
                path = root / 'client.json'
                path.write_text(json.dumps(config))
                result = subprocess.run([BINARY,'client','--config',str(path)],cwd=SDK,timeout=25,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                assert (result.returncode == 0) == passed, (label,result.stderr.decode())
                if require_report:
                    rows = json.loads(report.read_text())['results']
                    assert len(rows) == 1
                    assert rows[0]['status'] == ('passed' if passed else 'failed'), (label,rows)
                print(f'{label}: passed')
            for mode in ['503','reset','watchdog','redirect','canonical-rejection']:
                server.mode = mode
                run(f'http-{mode}',{},passed=mode=='canonical-rejection')
                if mode == 'watchdog': release.set()
            assert not redirected, 'endpoint credentials crossed redirect resource boundary'
            server.mode = 'redirect'
            # No report is required for failure before per-scenario acquisition (OAuth setup).
            config = dict(transport='http',endpoint=endpoint,scenarioFile=str(scenario),reportFile=str(root/'report.json'),auth={'mode':'oauth','tokenEndpoint':endpoint+'/token','clientId':'TEST-ONLY-client','clientSecret':'TEST-ONLY-secret','audience':'test'})
            (root/'oauth.json').write_text(json.dumps(config))
            result = subprocess.run([BINARY,'client','--config',str(root/'oauth.json')],cwd=SDK,timeout=25,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            assert result.returncode != 0 and not redirected, 'OAuth redirect followed'
            print('oauth-redirect: passed')
            peer = root/'peer.py'
            peer.write_text('''import json,sys,time
request=json.loads(sys.stdin.readline())
print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{'protocolVersion':'draft','manifest':{'transports':['stdio'],'authentication':[],'toolPaths':['native'],'contentCategories':[],'limits':{},'managedPolicy':{'scopes':['user'],'disableable':True},'correlationIdentityFields':['id','source'],'events':[{'event':'tool.before','modes':['intercept'],'capabilities':json.loads(sys.argv[2])}],'gaps':[]}}}),flush=True)
if sys.argv[1]=='blocked-write': time.sleep(60)
sys.stdin.readline()
if sys.argv[1]=='watchdog': time.sleep(60)
''')
            for mode in ['eof','watchdog','blocked-write']:
                if mode == 'blocked-write':
                    large = json.loads(json.dumps(case))
                    large['request']['params']['event']['tool']['input']['padding'] = 'x' * (4 * 1024 * 1024)
                    scenario.write_text(json.dumps({'version':1,'scenarios':[large]}))
                # Override fields without duplicate kwargs in the helper.
                report=root/'report.json'; report.unlink(missing_ok=True)
                config=dict(transport='stdio',scenarioFile=str(scenario),reportFile=str(report),auth={'mode':'none'},serverCommand=[sys.executable,str(peer),mode,json.dumps(CAPS)],serverConfig=str(root/'unused.json'))
                path=root/'stdio.json';path.write_text(json.dumps(config))
                result=subprocess.run([BINARY,'client','--config',str(path)],cwd=SDK,timeout=25,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                rows=json.loads(report.read_text())['results']
                assert result.returncode != 0 and rows[0]['status']=='failed', (mode,rows)
                print(f'stdio-{mode}: passed')
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

if __name__ == '__main__': main()
