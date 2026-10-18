'use strict';
let state = null, csrf = '', settingsLoaded = false, antivirusPolicyLoaded = false, startupLoaded = false, stopped = false;
if(location.hash.startsWith('#session=')){
 const token=location.hash.slice(9);
 if(/^[A-Za-z0-9_-]{43}$/.test(token))sessionStorage.setItem('sentinel-token',token);
 history.replaceState(null,'','#overview');
}
csrf=sessionStorage.getItem('sentinel-token')||'';
const $ = id => document.getElementById(id);
const list = value => Array.isArray(value) ? value : value == null ? [] : [value];
const fmt = value => { if (!value) return 'Unavailable'; const d = new Date(value); return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString([], {dateStyle:'medium',timeStyle:'short'}); };
const bytes = n => n == null ? 'Unavailable' : n >= 1073741824 ? (n / 1073741824).toFixed(1) + ' GB' : n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n.toLocaleString() + ' bytes';
function node(tag, text, cls) { const n = document.createElement(tag); if (text != null) n.textContent = String(text); if (cls) n.className = cls; return n; }
// Windows paths, publishers and event fields are untrusted display data. Keep
// them in text nodes; never render collected values through innerHTML.
function set(id, text) { $(id).textContent = text; }
function badge(text, type='neutral') { return node('span', text, 'badge ' + type); }
function clear(id) { const n = $(id); n.replaceChildren(); return n; }
function empty(id, text) { clear(id).append(node('div', text, 'empty')); }
function section(name) { return state?.snapshot?.sections?.[name]; }
function data(name) { const s = section(name); return s?.ok ? s.data : null; }
function checked(s) { return s === true ? ['On','good'] : s === false ? ['Off','bad'] : ['Unknown','neutral']; }
function row(parent, title, detail, value, cls='neutral') { const r = node('div',null,'row'), left = node('div'); left.append(node('strong', title)); if (detail) left.append(node('small',detail)); r.append(left, badge(value,cls)); parent.append(r); }
function unavailable(id, name) { const s = section(name); empty(id, s?.error || 'This check is not available yet. Refresh evidence to try again.'); }
function toast(message, error=false) { const n=$('toast'); n.textContent=message; n.className=error?'error':''; n.hidden=false; clearTimeout(toast.timer); toast.timer=setTimeout(()=>n.hidden=true,6000); }
function view(name) { if (!$('view-'+name)) name='overview'; document.querySelectorAll('.view').forEach(n=>n.hidden=n.id!=='view-'+name); document.querySelectorAll('[data-view]').forEach(n=>{n.classList.toggle('active',n.dataset.view===name); n.setAttribute('aria-current',n.dataset.view===name?'page':'false');}); history.replaceState(null,'','#'+name); window.scrollTo(0,0); }
async function request(url, body) {
 const options={credentials:'same-origin',cache:'no-store',headers:{'X-CSRF-Token':csrf},signal:AbortSignal.timeout(15000)};
 if(body!==undefined) Object.assign(options,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(body)});
 const response=await fetch(url,options); const value=await response.json();
 if(!response.ok) throw new Error(value.error||'The local service could not complete the request.'); return value;
}
async function action(url, body, message) { try {const value=await request(url,body); if(message)toast(message); await load(); return value;} catch(e){toast(e.message,true);return null;} }
async function load(){
 if(stopped)return;
 try { state=await request('/api/state');render(); }
 catch(e){$('connection').hidden=false;$('connection').className='notice error';set('connection',e.message+' If the service is stopped or your session expired, reopen Sentinel Local from its shortcut.');}
}
function table(id, headers, rows){const target=clear(id);if(!rows.length){target.append(node('div','No entries in this snapshot.','empty'));return;}const wrap=node('div',null,'table-wrap'),t=node('table'),head=node('thead'),hr=node('tr');headers.forEach(h=>hr.append(node('th',h)));head.append(hr);const body=node('tbody');rows.forEach(values=>{const tr=node('tr');values.forEach(v=>{const td=node('td');td.append(v instanceof Node?v:document.createTextNode(String(v??'Unavailable')));tr.append(td);});body.append(tr);});t.append(head,body);wrap.append(t);target.append(wrap);}
function field(parent, label, value, mono=false){const block=node('div',null,'detail-block');block.append(node('div',label,'detail-label'),node('div',value,'detail-value'+(mono?' mono':'')));parent.append(block);}
function ef(e,key){return Object.entries(e.fields||{}).find(([k])=>k.toLowerCase().replace(/[^a-z0-9]/g,'')===key.toLowerCase().replace(/[^a-z0-9]/g,''))?.[1]||'';}
function scanEvents(){return list(state.events).filter(e=>[1001,1002,1005].includes(e.id));}
function scanEventRows(events){return events.map(e=>{const skipped=e.id===1002&&/skipped/i.test(ef(e,'Stop Reason'));return [fmt(e.time),ef(e,'Scan Parameters')||'Defender scan',badge(e.id===1001?'Completed':skipped?'Skipped':e.id===1002?'Interrupted':'Failed',e.id===1001?'good':skipped?'neutral':'warn'),ef(e,'Stop Reason')||(e.id===1001?'Matching completion event 1001':'Event '+e.id)];});}
function metric(parent,label,value,detail){const box=node('article',null,'metric');box.append(node('div',label,'metric-label'),node('strong',value),node('small',detail));parent.append(box);}
function step(parent,index,title,copy){const r=node('div',null,'step'),text=node('div');text.append(node('strong',title),node('p',copy));r.append(node('span',String(index).padStart(2,'0'),'step-number'),text);parent.append(r);}
function render(){
 const sys=data('system'),d=data('defender'),p=data('preferences'),fw=list(data('firewall')),threats=data('threats');
 const layers=clear('layers'), metrics=clear('metrics'), steps=clear('next-steps');
 const errors=Object.entries(state.snapshot.sections||{}).filter(([,v])=>!v.ok).map(([k])=>k);
 const stale=state.snapshot.checkedAt && Date.now()-new Date(state.snapshot.checkedAt).getTime()>300000;
 const msg=state.refreshError||state.eventError||(errors.length?'Unavailable checks: '+errors.join(', ')+'.':stale?'Evidence is over five minutes old. Refresh for a current check.':!state.snapshot.checkedAt?'Reading Windows security evidence…':null);
 $('connection').hidden=!msg; if(msg){set('connection',msg);$('connection').className='notice'+(state.refreshError?' error':'');}
 set('device',sys?sys.computer+' · '+sys.os+(sys.administrator?' · Administrator':' · Standard user'):'This PC · waiting for Windows');
 set('refresh',state.refreshing?'↻ Refreshing…':'↻ Refresh evidence');$('refresh').disabled=state.refreshing;
 const real=d?.RealTimeProtectionEnabled,firewallKnown=fw.length===3&&fw.every(f=>typeof f.Enabled==='boolean'),allFirewall=firewallKnown&&fw.every(f=>f.Enabled===true);
 const live=!!state.snapshot.checkedAt&&!stale&&!state.refreshError;
 set('protection-title',real===true?(live?'Real-time protection is on.':'Last known protection: on.'):real===false?'Protection needs attention.':'Protection status unavailable.');
 set('protection-copy',real===true?'Defender is the active scan engine. Use the checks below to review protection layers and changes.':real===false?'Open Windows Security to review Defender. A console scan cannot replace real-time protection.':'Windows has not returned a current protection state. Missing evidence is shown as unknown.');
 metric(metrics,'WINDOWS REAL-TIME',checked(real)[0],live?'Additional Windows protection':'Check freshness below');
 metric(metrics,'FIREWALL PROFILES',firewallKnown?fw.filter(f=>f.Enabled===true).length+' / 3 on':'Unknown','Domain, Private and Public');
 metric(metrics,'THREAT HISTORY',section('threats')?.ok?list(threats).length+' records':'Unknown','Recorded detections · not a safety verdict');
 metric(metrics,'SIGNATURE AGE',d?.AntivirusSignatureAge!=null?d.AntivirusSignatureAge+' days':'Unknown',d?.AntivirusSignatureVersion||'No signature version available');
 for(const [label,val] of [['Defender antivirus',d?.AntivirusEnabled],['Real-time protection',real],['Behavior monitoring',d?.BehaviorMonitorEnabled],['Tamper protection',d?.IsTamperProtected],['All firewall profiles',firewallKnown?allFirewall:null]])row(layers,label,'',...checked(val));
 row(layers,'Potentially unwanted apps',p?'Windows PUA setting: '+p.PUAProtection:'',p?.PUAProtection===1?'Block':p?.PUAProtection===2?'Audit':p?.PUAProtection===0?'Off':'Unknown',p?.PUAProtection===1?'good':p?'warn':'neutral');
 row(layers,'Defender exclusions',p?.ExclusionsVisible?'Reported count across paths, processes and extensions':'Administrator access may be required',p?.ExclusionsVisible?String(p.ExclusionCount):'Unavailable','neutral');
 row(layers,'Registered antivirus products',list(data('securityProducts')).map(v=>v.displayName).join(' · ')||'Unavailable','Inventory','neutral');
 set('checked-time','Evidence: '+fmt(state.snapshot.checkedAt)+(stale?' · STALE':'')+' · signature update: '+fmt(d?.AntivirusSignatureLastUpdated));
 const notes=[];if(real===false||firewallKnown&&!allFirewall)notes.push(['Restore protection','Open Windows Security and review the disabled protection layers.']);
 if(data('restart')?.WindowsUpdate||data('restart')?.Servicing)notes.push(['Restart after saving your work','Windows reports a pending update or servicing restart. The console will not restart the PC automatically.']);
 const full=scanEvents().find(e=>/full/i.test(ef(e,'Scan Parameters')));
 if(full&&full.id!==1001)notes.push(['Complete a full scan when convenient','The latest recorded full scan was interrupted on '+fmt(full.time)+'. '+ef(full,'Stop Reason')+'. Keep the PC awake and on power for the next scan.']);
 const remote=list(data('remote'));if(remote.length)notes.push(['Review remote access apps',remote.map(t=>t.Name).join(', ')+' found. Support scammers rely on these tools; keep only the ones you recognize and use.']);
 const systemDisk=list(data('disks')).find(x=>x.DeviceID==='C:');if(systemDisk&&systemDisk.FreeSpace/systemDisk.Size<0.1)notes.unshift(['Free up disk space','C: has only '+bytes(systemDisk.FreeSpace)+' free. Open PC Cleaner to remove junk and old files; Windows slows down and updates fail on a full disk.']);
 if(sys&&!sys.administrator)notes.push(['Review protected settings in Windows','Some details, including Defender exclusions, may require administrator access. Use Windows Security for those checks.']);
 if(!state.eventError&&list(threats).length)notes.push(['Review detection actions','Open Windows Protection History to check remediation. Historical records can include already handled detections.']);
 if(p?.MAPSReporting!==undefined)notes.push(['Understand Defender cloud settings','This console stays local. Defender has its own Microsoft cloud reporting and sample submission policy; review it in Windows Security if needed.']);
 if(!notes.length)notes.push(['Keep reviewing unexpected changes','A normal status does not guarantee that all malware is absent. Scan unfamiliar downloads before opening them.']);
 notes.slice(0,4).forEach((n,i)=>step(steps,i+1,...n));
 set('monitor-status',state.monitor.error?'Monitor needs attention':state.monitor.lastChecked?'Local monitor running':'Monitor starting');
 set('monitor-time',state.monitor.error||'Last change check: '+fmt(state.monitor.lastChecked));
 set('footer-time','Windows evidence · '+fmt(state.snapshot.checkedAt));set('version','v'+state.version);
 if(state.eventError){empty('recent-scans',state.eventError);empty('scan-ledger',state.eventError);}else{table('recent-scans',['When','Scope','Result','Evidence'],scanEventRows(scanEvents().slice(0,3)));table('scan-ledger',['When','Scope','Result','Evidence'],scanEventRows(scanEvents()));}
 renderJobs();renderThreats();renderFiles();renderPersistence();renderNetwork();renderIntegrity();renderActivity();renderAntivirus();renderSelfTest();renderCleaner();
 if(!settingsLoaded){$('watch-downloads').checked=state.settings.watchDownloads;$('hashes').value=list(state.hashes).join('\n');settingsLoaded=true;}
 if(!startupLoaded&&state.startupLaunch){$('startup-enabled').checked=state.startupLaunch.enabled===true;startupLoaded=true;}
 set('startup-state',state.startupLaunch?.available?state.startupLaunch.enabled?'Enabled for this checkout, after you sign in.':'Off for this checkout. This is a user-session app, not a system service.':'Windows sign-in launch state is unavailable.');
 set('download-folder','Watched folder: '+state.downloadFolder);const session=clear('session-info');field(session,'Local data folder',state.dataFolder,true);field(session,'Session started',fmt(state.started));field(session,'Windows permissions',sys?.administrator?'Administrator':'Standard user; some protected details may be unavailable');
 const running=state.jobs.some(j=>j.status==='running');document.body.classList.toggle('busy',running);
 document.querySelectorAll('[data-job],#custom-form button,#inspect-form button,#av-custom-form button').forEach(b=>{let disabled=running;const kind=b.dataset.job||'';const av=state.antivirus;if(kind==='av-install')disabled||=!!av?.installed;else if(kind==='av-update')disabled||=!av?.installed;else if(kind.startsWith('av-')||b.closest('#av-custom-form'))disabled||=!av?.definitionsReady;b.disabled=disabled;});
}
function renderJobs(){
 const running=state.jobs.find(j=>j.status==='running');set('active-job',running?'RUNNING · '+running.kind.toUpperCase():'IDLE');
 const el=clear('jobs');el.classList.add('scan-history');if(!state.jobs.length){el.append(node('div','No actions launched from this app yet. Defender’s existing scan history appears below.','empty'));return;}
 state.jobs.filter(j=>!j.kind.startsWith('av-')).forEach(j=>{const r=node('div',null,'row'),left=node('div');left.append(node('strong',j.kind==='inspect'?'File inspection':j.kind==='update'?'Signature update':j.kind+' scan','job-title'));left.append(node('small',fmt(j.created)+(j.status==='running'?' · Elapsed '+Math.max(0,Math.floor((Date.now()-new Date(j.created))/60000))+' min · no percentage estimate':'')));left.append(node('small',j.detail));r.append(left,badge(j.status,j.status==='completed'?'good':j.status==='running'?'neutral':'warn'));el.append(r);});
}
function renderAntivirus(){
 const av=state.antivirus;if(!av)return;
 const ready=av.installed&&av.definitionsReady;
 set('protection-title',ready?'Independent antivirus is ready.':av.installed?'Install current virus signatures.':'Set up independent antivirus.');
 set('protection-copy',ready?'Sentinel scans with ClamAV, independent of Defender. New Downloads can be scanned after arrival; Windows protection stays active.':'Open Antivirus to install the verified engine and official signature databases. Windows protection continues independently.');
 const metrics=clear('av-metrics');metric(metrics,'SCANNING ENGINE',av.installed?'ClamAV '+av.version:'Not installed','Independent of Microsoft Defender');metric(metrics,'VIRUS DATABASES',av.definitionsReady?'Installed':'Not ready','Official signed ClamAV databases');metric(metrics,'DOWNLOAD SCANS',av.policy.scanDownloads?'Enabled':'Off','Post-arrival · while app is running');metric(metrics,'PRE-EXECUTION BLOCKING','Not implemented','Windows protection remains active');
 set('av-state',ready?'READY TO SCAN':av.installed?'SIGNATURES REQUIRED':'INSTALL REQUIRED');
 const p=av.progress;
 set('av-progress',p?p.phase+(p.totalBytes?' · '+bytes(p.bytes)+' of '+bytes(p.totalBytes):'')+(p.scanned!==undefined?' · '+p.scanned+' previously scanned; '+p.enumerated+' enumerated':'')+(p.batchFiles?' · batch '+(p.batchFinished||0)+' / '+p.batchFiles:'')+(p.message?' · '+p.message:''):'Last successful independent update: '+fmt(av.lastUpdate)+' · daily database age: '+(av.definitionAgeHours??'unknown')+' hours.');
 $('av-update-error').hidden=!av.updateError;if(av.updateError)set('av-update-error',av.updateError);
 $('av-cancel').disabled=!av.activeScan;
 if(!antivirusPolicyLoaded){$('av-auto-downloads').checked=av.policy.scanDownloads;$('av-auto-updates').checked=av.policy.autoUpdate;$('av-weekly-scan').checked=av.policy.weeklyScan;antivirusPolicyLoaded=true;}
 const findings=clear('av-findings');if(!av.detections.length)findings.append(node('div','No independent-engine findings recorded. Scan results are not a guarantee that every threat is absent.','empty'));
 av.detections.forEach(item=>{const block=node('div',null,'integrity-item'),head=node('div',null,'row');head.append(node('strong',item.path,'mono'),badge(item.verdict,item.verdict==='infected'?'bad':'warn'));block.append(head,node('p',item.signature+' · '+fmt(item.time),'footnote'),node('p','SHA-256: '+item.sha256,'footnote mono'),node('p','Action state: '+item.status,'footnote'));if(item.verdict==='infected'&&item.status==='open'){const b=node('button','Move to encrypted quarantine','danger');b.addEventListener('click',()=>{if(confirm('Quarantine this detected file? Its original will be removed only after a hash check and encrypted recovery copy. Windows/program files and changed files are blocked.'))action('/api/quarantine',{id:item.id},'File moved to encrypted quarantine.');});block.append(b);}findings.append(block);});
 const vault=clear('vault-items');if(!av.vault.length)vault.append(node('div','No files in quarantine. Only confirmed engine signature detections can be moved here.','empty'));
 av.vault.forEach(item=>{const block=node('div',null,'integrity-item');field(block,'Original file',item.path,true);field(block,'Vault state',item.status);field(block,'Stored bytes',bytes(item.bytes));if(item.recovery)field(block,item.status==='recovered'?'Recovered copy':'Last recovery attempt',item.recovery,true);if(item.restartDetail)field(block,'Restart audit',item.restartDetail);if(item.status!=='recovered'&&item.status!=='recovering'){const b=node('button','Recover a separate copy');b.addEventListener('click',()=>{if(confirm('Recover a potentially unsafe file into the private recovery folder with a .restored suffix? It will not overwrite an original or be opened automatically.'))action('/api/quarantine/recover',{id:item.id},'Recovered a separate copy. Review it before opening.');});block.append(b);}vault.append(block);});
 const jobs=state.jobs.filter(j=>j.kind.startsWith('av-')&&j.kind!=='av-selftest');table('av-jobs',['Started','Operation','Result','Evidence'],jobs.map(j=>[fmt(j.created),j.kind.replace('av-',''),badge(j.status,j.status==='completed'?'good':j.status==='running'?'neutral':'warn'),j.detail]));
}
function renderSelfTest(){
 const job=state.jobs.find(j=>j.kind==='av-selftest'),progress=state.selfTest?.progress;
 const result=job?.result,steps=progress?.steps||result?.steps||[],running=job?.status==='running';
 const passed=steps.filter(s=>s.status==='passed').length,complete=job?.status==='completed'&&result?.status==='completed';
 const metrics=clear('test-metrics');metric(metrics,'DIAGNOSTIC',running?'Running':complete?'Passed':job?job.status:'Ready','Harmless fixtures only');metric(metrics,'CHECKS PASSED',passed+' / 6','Engine → detection → quarantine → recovery');metric(metrics,'DURATION',result?.seconds!=null?result.seconds+' seconds':running?'In progress':'—',job?'Started '+fmt(job.created):'Run when ready');metric(metrics,'PC MALWARE VERDICT','Not measured','This diagnostic is not a PC safety scan');
 set('test-state',running?'RUNNING':complete?'ALL CHECKS PASSED':job?job.status.toUpperCase():'READY');
 set('test-progress',progress?.phase||(complete?'Complete. Both synthetic detections were quarantined and recovered. Temporary test data was removed.':job?.detail||'Ready when the independent engine and official signatures are installed.'));
 const el=clear('test-steps');if(!steps.length)el.append(node('div',running?'Loading the installed engine and official signatures…':'Your six verification steps will appear here.','empty'));
 steps.forEach((item,i)=>{const block=node('div',null,'diagnostic-step');step(block,i+1,item.title,item.detail);block.append(badge(item.status,item.status==='passed'?'good':'bad'));el.append(block);});
}
function renderThreats(){if(!section('threats')?.ok)return unavailable('threats','threats');const records=list(data('threats'));if(!records.length)return empty('threats','Windows returned no recorded threat detections. This is not proof that all malware is absent.');table('threats',['Detected','Threat ID','Action success','Resources'],records.map(t=>[fmt(t.InitialDetectionTime),t.ThreatID,t.ActionSuccess===true?'Yes':t.ActionSuccess===false?'No':'Unknown',list(t.Resources).join(' · ')]));}
function renderFiles(){const j=state.jobs.find(j=>j.kind==='inspect');if(!j)return;const el=clear('inspection');el.className='';if(j.status==='running'){el.append(node('p','Inspecting file without executing it…'));return;}if(!j.result){el.append(node('p',j.detail));return;}const r=j.result;field(el,'File',r.path,true);field(el,'Size',bytes(r.bytes));field(el,'SHA-256',r.sha256,true);field(el,'Signature status',r.signature.status==='UnknownError'?'Windows could not determine a signature. Some file types do not support Authenticode.':r.signature.status);field(el,'Publisher',r.signature.subject||'No publisher certificate returned');const script=/\.(ps1|bat|cmd|vbs|js|hta|py)$/i.test(r.path);field(el,'Review indicators',r.indicators.length?r.indicators.join(' · '):script?'No matching patterns in the inspected script portion. This is not a malware verdict.':'Pattern review does not apply to this file type. Use a Defender scan for malware detection.');field(el,'Your hash list',r.hashMatch?'MATCH — review this file against the source of your hash list.':'No match in your local list.');el.append(node('p',r.note,'footnote'));const b=node('button','Scan this file with Defender');b.addEventListener('click',()=>action('/api/job',{kind:'custom',path:r.path},'Custom scan started.'));el.append(b);}
function renderPersistence(){
 const el=clear('remote');
 if(!section('remote')?.ok){unavailable('remote','remote');}
 else{
  const tools=list(data('remote'));if(!tools.length)el.append(node('div','None of the 18 known remote access tools has a running process or Windows service.','empty'));
  tools.forEach(t=>row(el,t.Name,list(t.Services).join(' · ')||'No Windows service; process only',t.Running?'Running':'Installed',t.Running?'warn':'neutral'));
  el.append(node('p','Checks AnyDesk, TeamViewer, RustDesk, Chrome Remote Desktop, ScreenConnect, UltraViewer, Quick Assist and other common tools by service and process name. Nothing is approved, disabled or uninstalled; use PC Cleaner to uninstall a tool you do not use.','footnote'));
 }
 if(!section('startup')?.ok)return unavailable('startup','startup');
 table('startup',['Name','Launch target','Location','Review indicators'],list(data('startup')).map(s=>[s.Name,s.Target||'Target could not be extracted',s.Location,list(s.Indicators).join(' · ')||'None of the selected patterns']));
}
function renderNetwork(){const n=data('network');if(!n){unavailable('listeners','network');unavailable('connections','network');return;}table('listeners',['App','PID','Local address','Port','Binding scope'],list(n.listeners).map(r=>[r.Process||'Windows / unavailable',r.OwningProcess,r.LocalAddress,r.LocalPort,badge(r.Scope,r.Scope==='All interfaces'?'warn':'neutral')]));table('connections',['App','PID','Local port','Remote address','Remote port'],list(n.connections).map(r=>[r.Process||'Unavailable',r.OwningProcess,r.LocalPort,r.RemoteAddress,r.RemotePort]));}
function renderIntegrity(){const el=clear('watched');if(!state.integrity.length){el.append(node('div','No file baselines yet. Add an important file above.','empty'));return;}state.integrity.forEach(r=>{const block=node('div',null,'integrity-item'),head=node('div',null,'row');head.append(node('strong',r.path,'mono'),badge(r.status,r.status==='unchanged'?'good':'warn'));block.append(head,node('p','Baseline: '+r.hash,'footnote mono'),node('p','Latest: '+r.lastHash,'footnote mono'),node('p','Checked '+fmt(r.checked),'footnote'));const b=node('button','Remove watch','text-button');b.addEventListener('click',()=>action('/api/integrity/remove',{path:r.path},'Watch removed. The file has not been deleted.'));block.append(b);el.append(block);});}
function renderActivity(){if(!state)return;const el=clear('activity-list'),filter=$('activity-filter').value,items=state.activity.filter(a=>filter==='all'||a.level===filter);if(!items.length){el.append(node('div','No activity for this filter.','empty'));return;}items.forEach(a=>{const r=node('div',null,'activity-item'),copy=node('div');copy.append(node('strong',a.title),node('p',a.detail));r.append(node('span',null,'activity-marker '+a.level),node('time',fmt(a.time)),copy);el.append(r);});}
// Lists with checkboxes are rebuilt only when their data changes, so a 5-second
// refresh never clears the user's selection or scroll position.
function once(id,key,build){const el=$(id);if(el.dataset.key===key)return;el.dataset.key=key;el.replaceChildren();build(el);}
function check(value,checked=false){const box=node('input');box.type='checkbox';box.value=value;box.checked=checked;return box;}
function subtable(el,id,headers,rows){const wrap=node('div');wrap.id=id;el.append(wrap);table(id,headers,rows);}
function renderCleaner(){
 const c=state.cleaner;if(!c)return;
 const junk=list(c.junk),total=junk.reduce((s,j)=>s+j.bytes,0),bin=c.recycleBin,disk=list(data('disks')).find(d=>d.DeviceID==='C:');
 const metrics=clear('cleaner-metrics');
 metric(metrics,'JUNK FOUND',c.analyzed?bytes(total):'Not analyzed',c.analyzed?junk.reduce((s,j)=>s+j.files,0).toLocaleString()+' files · '+fmt(c.analyzed):'Run Analyze this PC');
 metric(metrics,'RECYCLE BIN',bin?bytes(bin.bytes):'Unknown',bin?bin.items.toLocaleString()+' items':'Analyze to measure');
 metric(metrics,'FREE ON C:',disk?bytes(disk.FreeSpace):'Unknown',disk?Math.round(disk.FreeSpace/disk.Size*100)+'% of '+bytes(disk.Size):'Waiting for Windows evidence');
 metric(metrics,'LAST CLEANUP',c.last?bytes(c.last.freed)+' freed':'Never',c.last?fmt(c.last.time):'Nothing deleted yet');
 const status=$('cleaner-status'),busy=c.busy?(c.progress||'Working')+'… Large folders can take a minute.':null;
 status.hidden=!(busy||c.error);status.className='notice'+(c.error&&!busy?' error':'');if(busy||c.error)set('cleaner-status',busy||c.error);
 document.querySelectorAll('#cleaner-analyze,#cleaner-form button,#cleaner-recycle').forEach(b=>b.disabled=!!c.busy);
 once('cleaner-junk',String(c.analyzed),el=>{
  if(!c.analyzed){el.append(node('div','Choose Analyze this PC to measure junk files. Nothing is deleted during analysis.','empty'));return;}
  const add=(id,title,detail,size,checked)=>{const label=node('label',null,'checkbox'),text=node('span');text.append(node('strong',title),node('small',detail));label.append(check(id,checked),text,badge(size,'neutral'));el.append(label);};
  junk.forEach(j=>add(j.id,j.title,j.detail,bytes(j.bytes)+' · '+j.files.toLocaleString()+' files',j.bytes>0));
  if(bin)add('recycle-bin','Recycle Bin','Permanently deletes everything already in the Recycle Bin.',bytes(bin.bytes)+' · '+bin.items.toLocaleString()+' items',false);
 });
 once('cleaner-review',String(c.analyzed)+'|'+list(c.review).map(f=>f.path).join('|'),el=>{
  if(!c.analyzed){el.append(node('div','Analyze this PC to list large and old files.','empty'));return;}
  subtable(el,'cleaner-review-table',['','File','Size','Modified','Why it is listed'],list(c.review).map(f=>[check(f.path),node('span',f.path,'mono'),bytes(f.bytes),fmt(f.modified*1000),f.reason]));
 });
 const query=$('program-search').value.trim().toLowerCase(),sort=$('program-sort').value;
 const programs=list(c.programs).filter(p=>!query||(p.name+' '+p.publisher).toLowerCase().includes(query)).sort((a,b)=>sort==='name'?a.name.localeCompare(b.name):sort==='installed'?(b.installed||'').localeCompare(a.installed||''):(b.bytes||0)-(a.bytes||0));
 once('cleaner-programs',query+'|'+sort+'|'+programs.map(p=>p.id).join(),el=>subtable(el,'cleaner-programs-table',['Program','Version','Size','Installed','For',''],programs.map(p=>{
  const name=node('div');name.append(node('strong',p.name),node('small',p.publisher||'Unknown publisher'));
  const b=node('button','Uninstall','danger');b.disabled=!p.command;
  b.addEventListener('click',()=>{if(confirm('Open the uninstaller for '+p.name+'?\n\nIt runs: '+p.command+'\n\nFollow its prompts to finish. Sentinel does not delete anything itself.'))action('/api/cleaner/uninstall',{id:p.id},'Uninstaller opened for '+p.name+'.');});
  return [name,p.version||'Unknown',p.bytes?bytes(p.bytes):'Unknown',p.installed||'Unknown',p.scope,b];})));
 once('cleaner-startup',list(c.startup).map(s=>s.id+s.enabled).join(),el=>subtable(el,'cleaner-startup-table',['App','Command','Where','Status',''],list(c.startup).map(s=>{
  const b=node('button',s.enabled?'Disable':'Enable',s.enabled?'danger':'');
  b.addEventListener('click',()=>action('/api/cleaner/startup',{id:s.id,enabled:!s.enabled},(s.enabled?'Disabled ':'Enabled ')+s.name+' at sign-in.'));
  return [s.name,node('span',s.command,'mono'),s.location+(s.needsAdmin?' · admin':''),badge(s.enabled?'Enabled':'Disabled',s.enabled?'good':'neutral'),b];})));
}
document.querySelectorAll('[data-view],[data-go]').forEach(b=>b.addEventListener('click',()=>view(b.dataset.view||b.dataset.go)));
window.addEventListener('hashchange',()=>view(location.hash.slice(1)));
$('refresh').addEventListener('click',()=>action('/api/refresh',{},'Refreshing Windows evidence…'));
document.querySelectorAll('[data-action="windows"]').forEach(b=>b.addEventListener('click',()=>action('/api/windows-security',{},'Opening Windows Security on this PC.')));
document.querySelectorAll('[data-job]').forEach(b=>b.addEventListener('click',()=>{const kind=b.dataset.job;if((kind==='full'||kind==='av-full')&&!confirm('Start a full scan now? It can take hours. Keep the PC awake and on power. Review skipped files and errors in the final result.'))return;action('/api/job',{kind},'Started '+kind+'.');view(kind==='av-selftest'?'selftest':kind.startsWith('av-')?'antivirus':'scans');}));
$('av-custom-form').addEventListener('submit',e=>{e.preventDefault();action('/api/job',{kind:'av-custom',path:$('av-path').value},'Independent scan started.');});
$('av-policy-form').addEventListener('submit',e=>{e.preventDefault();action('/api/antivirus/policy',{scanDownloads:$('av-auto-downloads').checked,autoUpdate:$('av-auto-updates').checked,weeklyScan:$('av-weekly-scan').checked},'Independent antivirus policy saved.');});
$('av-cancel').addEventListener('click',()=>action('/api/antivirus/cancel',{},'Cancellation requested for the independent scan.'));
$('custom-form').addEventListener('submit',e=>{e.preventDefault();action('/api/job',{kind:'custom',path:$('custom-path').value},'Custom scan started.');});
$('inspect-form').addEventListener('submit',e=>{e.preventDefault();action('/api/job',{kind:'inspect',path:$('inspect-path').value},'File inspection started.');});
$('integrity-form').addEventListener('submit',async e=>{e.preventDefault();const result=await action('/api/integrity/add',{path:$('integrity-path').value},'Local baseline saved.');if(result)$('integrity-path').value='';});
$('settings-form').addEventListener('submit',e=>{e.preventDefault();const hashes=$('hashes').value.split(/\s+/).filter(Boolean);action('/api/settings',{watchDownloads:$('watch-downloads').checked,hashes},'Settings saved.');});
$('startup-form').addEventListener('submit',e=>{e.preventDefault();action('/api/startup',{enabled:$('startup-enabled').checked},'Windows sign-in launch saved.');});
$('cleaner-analyze').addEventListener('click',()=>action('/api/cleaner/analyze',{},'Analyzing this PC. Nothing is deleted.'));
$('cleaner-form').addEventListener('submit',e=>{e.preventDefault();const picked=[...$('cleaner-junk').querySelectorAll('input:checked')].map(b=>b.value),categories=picked.filter(v=>v!=='recycle-bin'),recycleBin=picked.includes('recycle-bin');if(!picked.length)return toast('Choose at least one junk category.',true);if(!confirm('Clean the selected junk now?'+(recycleBin?'\n\nThe Recycle Bin will be emptied permanently.':'')))return;action('/api/cleaner/clean',{categories,recycleBin},'Cleaning selected junk…');});
$('cleaner-recycle').addEventListener('click',()=>{const paths=[...$('cleaner-review').querySelectorAll('input:checked')].map(b=>b.value);if(!paths.length)return toast('Select files to move first.',true);if(confirm('Move '+paths.length+' file(s) to the Recycle Bin? You can restore them from there.'))action('/api/cleaner/recycle',{paths},'Moved to the Recycle Bin.');});
$('program-search').addEventListener('input',()=>state&&renderCleaner());$('program-sort').addEventListener('change',()=>state&&renderCleaner());
document.querySelectorAll('[data-settings]').forEach(b=>b.addEventListener('click',()=>action('/api/windows-settings',{page:b.dataset.settings},'Opening Windows Settings.')));
$('activity-filter').addEventListener('change',renderActivity);$('print').addEventListener('click',()=>window.print());
document.querySelectorAll('a[href="/api/export"]').forEach(link=>link.addEventListener('click',async e=>{e.preventDefault();try{const report=await request('/api/export');const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const download=node('a');download.href=url;download.download='Sentinel-Local-security-report.json';document.body.append(download);download.click();download.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('Report exported locally.');}catch(error){toast(error.message,true);}}));
$('quit').addEventListener('click',async()=>{if(!confirm('Stop this local console and its change monitors? Defender protection continues. You can reopen the console with the launcher.'))return;const result=await action('/api/quit',{});if(result){stopped=true;set('connection','Console stopped. Defender protection continues independently. Use the launcher to reopen.');$('connection').hidden=false;toast('Local console stopped.');}});
view(location.hash.slice(1)||'overview');load();setInterval(load,5000);
