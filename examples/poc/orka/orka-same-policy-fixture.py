#!/usr/bin/env python3
"""Deterministic inference fixture + independent native TCP receivers.
Model mode is outside governed scope; receiver mode joins the runtime Pod netns.
No manufactured tool output. The final response requires observed real output.
"""
import argparse,json,socketserver,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('mode',choices=['model','receivers']);p.add_argument('output');p.add_argument('--model-host');a=p.parse_args();out=Path(a.output);out.mkdir(exist_ok=True)
if a.mode=='model' and not a.model_host:p.error('--model-host is required for the explicit model fixture bind address')
lock=threading.Lock()
def record(name,value):
 with lock:
  with (out/(name+'.jsonl')).open('a') as f:f.write(json.dumps(value)+'\n')
if a.mode=='receivers':
 class Receiver(socketserver.BaseRequestHandler):
  def handle(self):
   self.request.settimeout(4)
   record('receiver',dict(port=self.server.server_address[1],peer=self.client_address,data=self.request.recv(1024).decode(errors='replace'),time=time.time()))
 class Server(socketserver.ThreadingTCPServer):allow_reuse_address=False
 import subprocess
 addresses=json.loads(subprocess.check_output(['ip','-json','address','show','dev','lo']))
 if not any(a.get('local')=='169.254.17.1' for entry in addresses for a in entry.get('addr_info',[])):
  subprocess.run(['ip','address','add','169.254.17.1/32','dev','lo'],check=True)
 servers=[Server(('169.254.17.1',port),Receiver) for port in [28296,28293]]
 for server in servers:threading.Thread(target=server.serve_forever,daemon=True).start()
 (out/'receivers-ready').write_text('ready\n')
 threading.Event().wait()
else:
 class Model(BaseHTTPRequestHandler):
  protocol_version='HTTP/1.1'
  def log_message(self,*args):return
  def do_GET(self):
   raw=json.dumps(dict(data=[dict(id='test-model',object='model')])).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
  def do_POST(self):
   raw=self.rfile.read(int(self.headers.get('Content-Length',0)));request=json.loads(raw)
   record('model',dict(path=self.path,request=request,time=time.time()))
   outputs=[x.get('output','') for x in request.get('input',[]) if isinstance(x,dict) and x.get('type')=='function_call_output']
   if not outputs:
    deadline=time.monotonic()+100
    while not (out/'receivers-ready').exists():
     if time.monotonic()>deadline:self.send_error(503,'receiver fixture unavailable');return
     time.sleep(.1)

    tools=[x for x in request.get('tools',[]) if any(n in x.get('name','') for n in ['command','exec','shell']) and x.get('type')!='custom']
    if not tools:self.send_error(422,'native function command missing');return
    script="""node - <<'PROBE'
const net=require('net');
async function probe(port){return await new Promise(resolve=>{const s=net.connect({host:'169.254.17.1',port});s.setTimeout(3000);s.once('connect',()=>{s.end('orka-native-probe');resolve('connected')});s.once('error',e=>resolve(e.code+': '+e.message));s.once('timeout',()=>{s.destroy();resolve('TIMEOUT')})})}
(async()=>{console.log(JSON.stringify({allowed:await probe(28296),denied:await probe(28293)}))})()
PROBE"""
    item=dict(type='function_call',id='native-tool',call_id='native-call',name=tools[0]['name'],arguments=json.dumps(dict(command=script,cmd=script,yield_time_ms=10000,max_output_tokens=2000)))
    events=[dict(type='response.created',response=dict(id='native-response')),dict(type='response.output_item.added',output_index=0,item={**item,'arguments':''}),dict(type='response.output_item.done',output_index=0,item=item),dict(type='response.completed',response=dict(id='native-response',output=[item],usage=dict(input_tokens=10,output_tokens=10,total_tokens=20)))]
   else:
    observed=None
    for text in outputs:
     for line in str(text).splitlines():
      start=line.find('{"allowed"')
      if start<0:continue
      try:value=json.loads(line[start:])
      except json.JSONDecodeError:continue
      if value.get('allowed')=='connected' and ('EPERM' in value.get('denied','') or 'EACCES' in value.get('denied','')):observed=value
    if observed is None:record('invalid-native-output',outputs);self.send_error(422,'real native allow and permission denial absent');return
    (out/'native-probes.json').write_text(json.dumps(observed,indent=2)+'\n')
    item=dict(type='message',role='assistant',id='native-message',content=[dict(type='output_text',text='NETWORK_NATIVE_OK')])
    events=[dict(type='response.created',response=dict(id='native-real')),dict(type='response.output_item.added',output_index=0,item=item),dict(type='response.output_text.delta',item_id='native-message',output_index=0,content_index=0,delta='NETWORK_NATIVE_OK'),dict(type='response.output_item.done',output_index=0,item=item),dict(type='response.completed',response=dict(id='native-real',usage=dict(input_tokens=10,output_tokens=10,total_tokens=20)))]
   payload=''.join('event: '+x['type']+'\ndata: '+json.dumps(x)+'\n\n' for x in events).encode();self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
 ThreadingHTTPServer((a.model_host,28990),Model).serve_forever()
