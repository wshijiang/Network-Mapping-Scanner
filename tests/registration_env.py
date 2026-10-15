"""Process-level env registration regression; only talks to a local HTTPS fixture.

Run after cargo build: python3 tests/registration_env.py target/debug/scanner-rs
Requires Python 3 and OpenSSL; no real scanning tools or remote server are used.
"""
import http.server, ssl, threading, subprocess, tempfile, pathlib, os, sqlite3, json, time, signal, uuid
import sys
BINARY=str(pathlib.Path(sys.argv[1] if len(sys.argv)>1 else 'target/debug/scanner-rs').resolve())
with tempfile.TemporaryDirectory(prefix='registration-check-') as tmp:
    root=pathlib.Path(tmp)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    calls=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def reply(self,code,body):
            data=json.dumps(body).encode(); self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length','0')))
            if self.path=='/api/scanner/register':
                token=self.headers.get('Authorization','').removeprefix('Bearer '); calls.append(token)
                if token=='fixture-rejected': self.reply(401,{})
                else: self.reply(200,{'runtime_token':'runtime-'+str(len(calls))})
            else: self.reply(200,{'success':True,'data':{}})
        def do_GET(self):
            if self.path.startswith('/api/task/'):
                self.send_response(204)
                self.end_headers()
            else:
                self.reply(200,{'success':True,'data':{}})
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(root/'cert.pem',root/'key.pem'); server.socket=context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    port=server.server_address[1]; scanner_id=str(uuid.uuid4()); database=root/'state.sqlite3'
    base=dict(os.environ, NM__SCANNER__C_SERVER='127.0.0.1',NM__SCANNER__C_PORT=str(port),NM__SCANNER__VERIFY_TLS='false',NM__SCANNER__SCANNER_PATH='/bin/true',NM__SERVICE_DETECTION__ENABLED='false',NM__NETWORK__IPV4_ENABLED='false',NM__NETWORK__IPV6_ENABLED='false',NM__REGISTRATION__SCANNER_ID=scanner_id,NO_PROXY='127.0.0.1,localhost')
    def identity():
        if not database.exists(): return None
        try:
            with sqlite3.connect(database) as db: return db.execute('SELECT scanner_id,runtime_token FROM scanner_identity').fetchone()
        except sqlite3.OperationalError: return None
    def run(token, expected, fail=False, health=False):
        env=base.copy()
        if token is not None: env['NM__REGISTRATION__TOKEN']=token
        log=root/('run-'+str(time.time_ns())+'.log')
        args=[BINARY,'--config-source','env','--database',str(database),'--state-file',str(root/'legacy.json'),'--log-directory',str(root/'logs')]
        if health: args+=['--health-check']
        with log.open('wb') as out:
            process=subprocess.Popen(args,cwd=root,env=env,stdout=out,stderr=out)
            try:
                deadline=time.monotonic()+12
                if fail:
                    process.wait(timeout=12)
                    if not health: assert process.returncode!=0
                else:
                    while time.monotonic()<deadline:
                        if process.poll() is not None: raise AssertionError(log.read_text())
                        if identity()==(scanner_id,expected): break
                        time.sleep(.05)
                    else: raise AssertionError('registration persistence timeout: '+log.read_text())
                    time.sleep(.25)
                    assert process.poll() is None, 'scanner did not continue after identity setup: '+log.read_text()
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                    try: process.wait(timeout=8)
                    except subprocess.TimeoutExpired: process.kill();process.wait()
        assert identity()==(scanner_id,expected)
        text=log.read_text()
        for secret in ['fixture-first','fixture-second','fixture-rejected']:
            assert secret not in text, 'registration token leaked to logs'
    run('fixture-first','runtime-1'); assert len(calls)==1
    run('fixture-first','runtime-1'); assert len(calls)==1
    run(None,'runtime-1'); assert len(calls)==1
    run('fixture-second','runtime-2'); assert len(calls)==2
    run('fixture-rejected','runtime-2',fail=True); assert len(calls)==3
    run('fixture-second','runtime-2'); assert len(calls)==3
    # A new token in env must not be consumed by a health-check command.
    run('fixture-health-only','runtime-2',fail=True,health=True); assert len(calls)==3
    # Changing IDs must not orphan results waiting for upload.
    with sqlite3.connect(database) as db:
        db.execute('INSERT INTO pending_upload VALUES(?,?,?,?,?,unixepoch())',
                   (f'https://127.0.0.1:{port}',scanner_id,str(uuid.uuid4()),str(uuid.uuid4()),0))
    base['NM__REGISTRATION__SCANNER_ID']=str(uuid.uuid4())
    run('fixture-new-id','runtime-2',fail=True); assert len(calls)==3
    server.shutdown()
    print('PASS: first env registration, restart, credential removal, token rotation, failed rotation rollback, health-check isolation, pending-result identity guard, secret-free logs')
