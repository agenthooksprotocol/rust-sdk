#!/usr/bin/env python3
"""Local Rust self-pair smoke test using central fixtures, never writes shared files."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import ssl
import urllib.error
import urllib.request

SDK = Path(__file__).resolve().parents[1]
SHARED = SDK.parent / 'agent-hooks-protocol' / 'interop'
def load(name):
    spec = importlib.util.spec_from_file_location(name, SHARED / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def write(path, value):
    path.write_text(json.dumps(value))
    return str(path)

def main():
    auth = load('auth')
    scenarios = load('generate_scenarios').build()
    binary = str(SDK / 'target/debug/interop')
    with tempfile.TemporaryDirectory(prefix='ahp-rust-') as tmp, auth.Issuer() as issuer:
        directory = Path(tmp)
        scenario = write(directory / 'scenarios.json', scenarios)
        for transport, mode in [('stdio','none')] + [('http', m) for m in ['none','bearer','oauth','workload','mtls']]:
            readiness = directory / 'ready.json'
            readiness.unlink(missing_ok=True)
            report = directory / 'report.json'
            config = dict(transport=transport, scenarioFile=scenario, readinessFile=str(readiness), auth=auth.configuration(mode, SHARED / 'fixtures', 'server', issuer))
            server_config = write(directory / 'server.json', config)
            client_config = dict(transport=transport, scenarioFile=scenario, reportFile=str(report), auth=auth.configuration(mode, SHARED / 'fixtures', 'client', issuer))
            server = None
            try:
                if transport == 'http':
                    server = subprocess.Popen([binary, 'server', '--config',server_config],cwd=SDK)
                    deadline = time.monotonic() + 15
                    while not readiness.exists():
                        if server.poll() is not None: raise RuntimeError('server exited before ready')
                        if time.monotonic() > deadline: raise TimeoutError('readiness deadline')
                        time.sleep(.02)  # readiness poll only; never establishes effect ordering
                    client_config['endpoint'] = json.loads(readiness.read_text())['endpoint']
                    endpoint = client_config['endpoint'].removesuffix('/intercept')
                    if mode in ('bearer','oauth','workload'):
                        bad = urllib.request.Request(endpoint+'/capabilities',headers={'Authorization':'Bearer invalid'})
                        try:
                            urllib.request.urlopen(bad,timeout=5)
                            raise AssertionError('unauthenticated capabilities admitted')
                        except urllib.error.HTTPError as error:
                            assert error.code == 401
                    elif mode == 'mtls':
                        for cert in (None, 'untrusted-client'):
                            context = ssl.create_default_context(cafile=str(SHARED/'fixtures/ca.pem'))
                            if cert: context.load_cert_chain(str(SHARED/f'fixtures/{cert}.pem'),str(SHARED/f'fixtures/{cert}-key.pem'))
                            try:
                                urllib.request.urlopen(endpoint+'/capabilities',context=context,timeout=5).read()
                                raise AssertionError('untrusted TLS client admitted')
                            except (ssl.SSLError, urllib.error.URLError, ConnectionError): pass
                    control = json.loads(readiness.read_text())['controlEndpoint']
                    receipts = json.load(urllib.request.urlopen(control+'/receipts',timeout=5))
                    assert receipts['requests'] == [], 'auth failures produced accepted receipts'

                else:
                    client_config.update(serverCommand=[binary,'server'],serverCwd=str(SDK),serverConfig=server_config)
                path = write(directory / 'client.json',client_config)
                result = subprocess.run([binary,'client','--config',path],cwd=SDK,timeout=60)
                rows = json.loads(report.read_text())['results'] if report.exists() else []
                failed = [r for r in rows if r['status'] != 'passed']
                if result.returncode or failed:
                    print(json.dumps(failed[:8],indent=2))
                    raise AssertionError(f'{transport}/{mode}: exit={result.returncode}')
                print(f'{transport}/{mode}: {len(rows)} passed')
                if server:
                    endpoint = json.loads(readiness.read_text())['controlEndpoint']
                    request = urllib.request.Request(endpoint+'/shutdown',data=b'{}',headers={'Content-Type':'application/json'})
                    urllib.request.urlopen(request,timeout=5).read()
                    server.wait(timeout=5)
            finally:
                if server and server.poll() is None: server.kill(); server.wait(timeout=5)
                report.unlink(missing_ok=True)
        assert issuer.issued > 0
if __name__ == '__main__':
    main()
