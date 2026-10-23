'use strict';
// TEST-only normal provider entrypoint, AFTER unchanged runtime held-exec gate.
const fs = require('fs');
const net = require('net');
const ready = '/tmp/poc-network-independent-receivers-ready';
const resultPath = '/tmp/poc-network-independent-result.json';
const deadline = Date.now() + 45000;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function run() {
  while (!fs.existsSync(ready)) {
    if (Date.now() > deadline) throw new Error('actual receiver acknowledgment missing');
    await delay(50);
  }
  const ack = JSON.parse(fs.readFileSync(ready, 'utf8'));
  if (!ack.token || !ack.task_uid || !ack.pod_uid || !ack.container_id) throw new Error('incomplete fixture identity');
  if (fs.existsSync(resultPath)) throw new Error('ambiguous previous result; refusing overwrite');
  const result = await new Promise(resolve => {
    const s = net.connect({host:'169.254.17.1', port:28296});
    s.setTimeout(3000);
    s.once('connect', () => s.end('orka-network-independent-probe', () => resolve({connected:true,write_completed:true,error:null})));
    s.once('error', e => resolve({connected:false,write_completed:false,error:e.code,message:e.message}));
    s.once('timeout', () => {s.destroy();resolve({connected:false,write_completed:false,error:'TIMEOUT'});});
  });
  fs.writeFileSync(resultPath, JSON.stringify({ack,pid:process.pid,uid:process.getuid(),cwd:process.cwd(),...result}), {mode:0o644,flag:'wx'});
  console.error('ORKA_NETWORK_INDEPENDENT_NATIVE_RESULT '+JSON.stringify(result));
  // Deliberately failed initialization avoids model retries under empty ceiling.
  // Neither terminal status nor inference result is manufactured by the fixture.
  if (ack.scenario === 'empty') process.exitCode=23;
}
run().catch(e => {console.error('ORKA_NETWORK_INDEPENDENT_FIXTURE_FAILURE '+e.message);process.exitCode=1;});
