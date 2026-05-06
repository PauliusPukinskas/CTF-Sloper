'use strict';

const S = { prefs: null, projects: [], current: null, activePage: 'create', activeTab: 'overview', files: [], poller: null };
const tabs = [
  ['overview', 'Overview'], ['flags', 'Flags'], ['artifacts', 'Artifacts'], ['files', 'Files'],
  ['logs', 'Logs'], ['settings', 'Settings'], ['tools', 'Manual tools']
];
const fileTools = ['strings', 'exiftool', 'binwalk', 'foremost', 'zsteg', 'steghide_info', 'tshark_quick', 'file', 'xxd_head'];

function qs(id){ return document.getElementById(id); }
function esc(x){ return String(x ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function enc(x){ return encodeURIComponent(String(x ?? '')); }
async function fetchJson(url, opts){ const r = await fetch(url, opts || {}); const t = await r.text(); try { return JSON.parse(t); } catch(e){ return {ok:false, error:t || String(e), status:r.status}; } }
function copyText(x){ navigator.clipboard?.writeText(String(x)).catch(()=>{}); }
function showPage(name){ S.activePage = name; document.querySelectorAll('.page').forEach(p=>p.classList.add('hidden')); qs('page-'+name)?.classList.remove('hidden'); document.querySelectorAll('.nav button').forEach(b=>b.classList.remove('on')); qs('nav-'+name)?.classList.add('on'); if(name==='projects') loadProjects(); if(name==='profile') renderProfile(); if(name==='tools') loadTools(); }

async function init(){ await loadPreferences(); renderCreate(); renderProfile(); await loadProjects(); showPage('create'); }
document.addEventListener('DOMContentLoaded', init);

async function loadPreferences(){
  const j = await fetchJson('/api/preferences');
  S.prefs = j.preferences || {};
  S.formats = j.formats || {}; S.attackPresets = j.attack_presets || {}; S.difficulties = j.difficulties || ['easy','medium','hard','multi_step']; S.categories = j.categories || [];
  const total = j.project_counter?.total ?? 0;
  qs('sideStats').innerHTML = `<p>Projects: <b>${esc(total)}</b></p><p>Default: <b>${esc(S.prefs.flag_label || S.prefs.flag_format || 'ctf_cs')}</b></p><p>Preset: <b>${esc(S.prefs.attack_preset || 'balanced')}</b></p>`;
}
function formatOptions(selected){
  const entries = Object.entries(S.formats || {ctf_cs:{label:'ctf_cs{...}'}, ctf_cm:{label:'ctf_cm{...}'}, flag:{label:'flag{...}'}, any_prefix:{label:'anyPrefix{...}'}, braces_only:{label:'{...}'}, custom_regex:{label:'custom regex'}});
  return entries.map(([k,v])=>`<option value="${esc(k)}" ${selected===k?'selected':''}>${esc(v.label || k)}</option>`).join('');
}
function presetOptions(selected){ return Object.keys(S.attackPresets || {quick:1,balanced:1,deep:1,hardcore:1}).map(k=>`<option value="${esc(k)}" ${selected===k?'selected':''}>${esc(k)}</option>`).join(''); }
function difficultyOptions(selected){ return (S.difficulties || ['easy','medium','hard','multi_step']).map(k=>`<option value="${esc(k)}" ${selected===k?'selected':''}>${esc(k.replace('_','-'))}</option>`).join(''); }

function renderCreate(){
  const p = S.prefs || {};
  qs('page-create').innerHTML = `<div class="card"><h2>Create challenge project</h2><p class="sub">Upload challenge files, choose the expected flag wrapper and how aggressively Sloper should decode/chain artifacts.</p>
  <div id="drop" class="drop"><b>Drop files or ZIP here</b><br><br><button class="btn primary" onclick="qs('fileInput').click()">Select files</button><input id="fileInput" class="fileInput" type="file" multiple onchange="setFiles(this.files)"><div id="fileCount" class="sub">No files selected</div></div>
  <br><div class="grid"><label>Title<input id="title" placeholder="challenge name"></label><label>Category<select id="category"><option value="auto">auto</option><option>crypto</option><option>stego</option><option>forensics</option><option>reversing</option><option>web</option><option>osint</option><option>misc</option></select></label></div>
  <br><textarea id="statement" placeholder="Task statement / hint / flag format text"></textarea><br><br>
  ${settingsFormHtml('create', p)}
  <div class="row"><label class="pill"><input type="checkbox" id="autoStart" checked> auto start</label><button class="btn primary" onclick="createProject()">Create + Solve</button><span class="pill">bounded multi-step</span></div></div>`;
  const drop = qs('drop');
  drop.ondragover = ev => { ev.preventDefault(); drop.style.borderColor = 'var(--accent)'; };
  drop.ondragleave = () => { drop.style.borderColor = 'var(--line)'; };
  drop.ondrop = ev => { ev.preventDefault(); drop.style.borderColor = 'var(--line)'; setFiles(ev.dataTransfer.files); };
}
function settingsFormHtml(prefix, p){
  return `<div class="grid"><label>flag format<select id="${prefix}FlagFormat">${formatOptions(p.flag_format || 'ctf_cs')}</select></label><label>custom regex<input id="${prefix}CustomRegex" value="${esc(p.custom_flag_regex || '')}" placeholder="KEY-[A-Z0-9-]+"></label><label>attack preset<select id="${prefix}AttackPreset">${presetOptions(p.attack_preset || 'balanced')}</select></label><label>difficulty<select id="${prefix}Difficulty">${difficultyOptions(p.difficulty || 'medium')}</select></label><label>max depth<input id="${prefix}MaxDepth" type="number" min="0" max="10" value="${esc(p.max_depth ?? 2)}"></label><label>max artifacts<input id="${prefix}MaxArtifacts" type="number" min="50" max="15000" value="${esc(p.max_artifacts ?? 800)}"></label></div><br>`;
}
function readSettings(prefix){
  const ff = qs(prefix+'FlagFormat')?.value || 'ctf_cs';
  const prefixMap = {ctf_cs:'ctf_cs', ctf_cm:'ctf_cm', flag:'flag', picoctf:'picoCTF', htb:'HTB'};
  return { flag_format: ff, flag_prefix: prefixMap[ff] || (S.prefs?.flag_prefix || 'ctf_cs'), custom_flag_regex: qs(prefix+'CustomRegex')?.value || '', attack_preset: qs(prefix+'AttackPreset')?.value || 'balanced', difficulty: qs(prefix+'Difficulty')?.value || 'medium', max_depth: Number(qs(prefix+'MaxDepth')?.value || 2), max_artifacts: Number(qs(prefix+'MaxArtifacts')?.value || 800) };
}
function setFiles(list){ S.files = Array.from(list || []); qs('fileCount').textContent = S.files.length ? S.files.map(f=>f.name).join(', ') : 'No files selected'; if(!qs('title').value && S.files[0]) qs('title').value = S.files[0].name; }
async function createProject(){
  if(!S.files.length){ alert('Add files first'); return; }
  const fd = new FormData(); S.files.forEach(f=>fd.append('files', f));
  fd.append('title', qs('title').value || S.files[0].name); fd.append('statement', qs('statement').value || ''); fd.append('category', qs('category').value || 'auto'); fd.append('auto_start', qs('autoStart').checked ? 'true' : 'false');
  const st = readSettings('create'); Object.entries(st).forEach(([k,v])=>fd.append(k, String(v)));
  const j = await fetchJson('/api/projects', {method:'POST', body:fd});
  if(!j.ok){ alert(j.error || 'create failed'); return; }
  await loadProjects(); showPage('projects'); await openProject(j.id); pollProject(j.id);
}

async function loadProjects(){ const j = await fetchJson('/api/projects'); S.projects = j.projects || []; renderProjects(); await loadPreferences(); }
function renderProjects(){
  const list = S.projects.map(p=>`<button class="btn" onclick="openProject('${esc(p.id)}')"><b>${esc(p.title || p.id)}</b><br><span class="sub">${esc(p.category || '')} · ${esc(p.runtime_status || p.stage || '')} · ${esc(p.progress ?? 0)}%</span></button>`).join('') || '<p class="warn">No projects yet.</p>';
  qs('page-projects').innerHTML = `<div class="grid"><div class="card"><div class="row between"><h2>Projects</h2><button class="btn" onclick="loadProjects()">Refresh</button></div><div class="list">${list}</div></div><div id="projectPanel">${S.current ? projectHtml(S.current) : '<div class="card"><h2>No project open</h2></div>'}</div></div>`;
}
async function openProject(pid){ const j = await fetchJson('/api/projects/'+enc(pid)); S.current = j; S.activeTab = 'overview'; renderProjects(); pollProject(pid); }
function pollProject(pid){ clearInterval(S.poller); S.poller = setInterval(async()=>{ if(S.current?.project?.id !== pid) return; const j = await fetchJson('/api/projects/'+enc(pid)); S.current = j; const panel = qs('projectPanel'); if(panel) panel.innerHTML = projectHtml(j); const status = j.job?.status || ''; if(status === 'done' || status === 'error' || status === 'cancelled') clearInterval(S.poller); }, 2500); }
function setTab(t){ S.activeTab = t; const panel = qs('projectPanel'); if(panel && S.current) panel.innerHTML = projectHtml(S.current); }
function projectHtml(j){
  const meta = j.project || {}, job = j.job || {}, rep = j.report || {}, sum = rep.summary || {}, files = rep.files || [];
  const tabButtons = tabs.map(([id,label])=>`<button class="btn ${S.activeTab===id?'primary':''}" onclick="setTab('${id}')">${esc(label)}</button>`).join('');
  return `<div class="card"><div class="row between"><div><h2>${esc(meta.title || 'Project')}</h2><div class="sub">${esc(meta.id || '')} · ${esc(meta.category || '')} · ${esc(sum.preferred_flag_format || '')}</div></div><div class="row"><button class="btn primary" onclick="startProject('${esc(meta.id)}')">Start</button><button class="btn danger" onclick="stopProject('${esc(meta.id)}')">Stop</button></div></div>${metricsHtml(sum, files, job)}<div class="progress"><div class="bar" style="width:${Number(job.progress || 0)}%"></div></div><p class="sub">${esc(job.stage || '')}</p></div><div class="card"><div class="tabs">${tabButtons}</div>${tabHtml(S.activeTab, meta, sum, files, j)}</div>`;
}
function metricsHtml(sum, files, job){ return `<div class="grid"><div class="metric"><b>${esc(job.progress ?? 0)}%</b><div class="sub">progress</div></div><div class="metric"><b>${files.length}</b><div class="sub">files</div></div><div class="metric"><b>${(sum.flags||[]).length}</b><div class="sub">promoted flags</div></div><div class="metric"><b>${(sum.related_candidate_flags||[]).length}</b><div class="sub">related candidates</div></div><div class="metric"><b>${(sum.artifacts||[]).length}</b><div class="sub">artifacts</div></div><div class="metric"><b>${esc(sum.v115_triage?.version || sum.v114_triage?.version || sum.v113_evidence?.version || sum.v110_fast_summary?.version || 'fast')}</b><div class="sub">engine</div></div><div class="metric"><b>${esc(sum.v115_triage?.best_score ?? sum.v114_triage?.best_confidence ?? sum.v113_evidence?.promoted ?? 0)}</b><div class="sub">best confidence</div></div><div class="metric"><b>${esc(sum.v115_triage?.trusted ?? sum.v114_triage?.high_confidence ?? 0)}</b><div class="sub">high confidence</div></div></div><br>`; }
function tabHtml(tab, meta, sum, files, j){
  if(tab==='flags') return flagsHtml(sum);
  if(tab==='artifacts') return artifactsHtml(sum.artifacts || []);
  if(tab==='files') return filesHtml(files);
  if(tab==='logs') return `<button class="btn" onclick="loadLog('${esc(meta.id)}')">Load latest log</button><div id="logBox"><pre>${esc(j.log || '')}</pre></div>`;
  if(tab==='settings') return projectSettingsHtml(meta);
  if(tab==='tools') return manualToolsHtml(files);
  return overviewHtml(sum);
}
function triageHtml(sum){ const v=sum.v115_triage||null; const t=v||sum.v114_triage||{}; if(v) return `<div class="find"><b>v115 live competition triage</b><p class="sub">best: ${esc(v.best_flag||'none')} · score ${esc(v.best_score||0)} · trusted ${esc(v.trusted||0)} · promising ${esc(v.promising||0)} · manual ${esc(v.manual_review||0)}</p><p class="sub">source: ${esc(v.best_source||'')} · priority artifacts ${esc(v.priority_artifacts||0)}</p><p class="sub">${esc(v.operator_hint||'')}</p></div>`; return `<div class="find"><b>v114 operator triage</b><p class="sub">best: ${esc(t.best_flag||'none')} · confidence ${esc(t.best_confidence||0)}% · high ${esc(t.high_confidence||0)} · medium ${esc(t.medium_confidence||0)} · related ${esc(t.low_or_related||0)}</p><p class="sub">${esc(t.operator_hint||'')}</p></div>`; }

function overviewHtml(sum){ return `${triageHtml(sum)}<h3>Best flags</h3>${flagsHtml(sum, 8)}<h3>Clean artifact queue</h3>${artifactsHtml((sum.artifacts||[]).slice(0,12))}`; }
function flagsHtml(sum, limit){ const flags=(sum.flags||[]).slice(0,limit||120); const related=(sum.related_candidate_flags||[]).slice(0,30); return `${flags.map(f=>flagRow(f)).join('') || '<p class="warn">No promoted flag yet.</p>'}${related.length?'<h3>Related candidates</h3>'+related.map(f=>flagRow(f,true)).join(''):''}`; }
function flagRow(f, weak){ const val = f.preferred_flag || f.flag || f.value || ''; const conf = f.confidence ?? ''; const risk = f.risk ?? ''; const verdict = f.verdict || (weak?'related':'promoted'); const chain = f.chain_text || (Array.isArray(f.chain)?f.chain.join(' → '):f.source||''); const why = Array.isArray(f.why)?f.why.join(', '):(f.why||''); const warn = Array.isArray(f.warnings)?f.warnings.join(', '):(f.warnings||''); return `<div class="flag"><div class="row between"><b class="${weak?'warn':'ok'}">${esc(val)}</b><button class="btn" onclick="copyText('${esc(val)}')">copy</button></div><div class="row"><span class="pill">${esc(verdict)}</span>${conf!==''?`<span class="pill">confidence ${esc(conf)}%</span>`:''}${risk!==''?`<span class="pill">risk ${esc(risk)}%</span>`:''}<span class="pill">score ${esc(f.score||f.rank_score||0)}</span></div><div class="sub">${esc(f.file||'')} · ${esc(chain)}</div>${why?`<div class="sub ok">why: ${esc(why)}</div>`:''}${warn?`<div class="sub warn">warn: ${esc(warn)}</div>`:''}</div>`; }
function artifactsHtml(items){ if(!items.length) return '<p class="warn">No artifacts yet.</p>'; return items.map(a=>`<div class="find artifact"><div><span class="score">${esc(a.score||0)}</span><br><span class="pill">${esc(a.kind||'artifact')}</span></div><div><b>${esc(a.name||a.path||a.url||'artifact')}</b><p class="sub">${esc(a.source||'')} · ${esc(a.file||'')} · ${esc(a.note||'')}</p></div><div class="row">${a.path?`<a class="btn" target="_blank" href="/api/raw?path=${enc(a.path)}">open</a>`:''}${a.url?`<a class="btn" target="_blank" href="${esc(a.url)}">url</a>`:''}</div></div>`).join(''); }
function filesHtml(files){ return files.map(f=>`<div class="find"><div class="row between"><div><b>${esc(f.rel||f.name)}</b><div class="sub">${esc(f.kind||'')} · ${esc(f.size||0)} bytes</div></div><div class="row"><button class="btn" onclick="previewFile('${enc(f.path)}')">preview</button>${f.path?`<a class="btn" target="_blank" href="/api/raw?path=${enc(f.path)}">raw</a>`:''}</div></div><div id="preview-${esc(f.path||f.name)}"></div></div>`).join('') || '<p class="warn">No files.</p>'; }
async function previewFile(path){ const j=await fetchJson('/api/raw_info?path='+path); alert(JSON.stringify(j,null,2)); }
function projectSettingsHtml(meta){ const p = meta.solver_settings || S.prefs || {}; return `<h3>Project solver settings</h3>${settingsFormHtml('project', p)}<button class="btn primary" onclick="saveProjectSettings('${esc(meta.id)}')">Save project settings</button><pre>${esc(JSON.stringify(p,null,2))}</pre>`; }
async function saveProjectSettings(pid){ const st=readSettings('project'); const j=await fetchJson('/api/projects/'+enc(pid)+'/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(st)}); if(!j.ok) alert(j.error||'failed'); else await openProject(pid); }
function manualToolsHtml(files){ const options = files.map(f=>`<option value="${esc(f.path||'')}">${esc(f.rel||f.name)}</option>`).join(''); return `<label>file<select id="toolFile">${options}</select></label><br><label>tool<select id="toolName">${fileTools.map(t=>`<option>${esc(t)}</option>`).join('')}</select></label><br><button class="btn primary" onclick="runTool()">Run tool</button><div id="toolOut"></div>`; }
async function runTool(){ const path=qs('toolFile').value, tool=qs('toolName').value; const j=await fetchJson('/api/run_tool',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path,tool})}); qs('toolOut').innerHTML = `<pre>${esc(JSON.stringify(j,null,2))}</pre>`; }
async function startProject(pid){ await fetchJson('/api/projects/'+enc(pid)+'/start',{method:'POST'}); await openProject(pid); }
async function stopProject(pid){ await fetchJson('/api/projects/'+enc(pid)+'/stop',{method:'POST'}); await openProject(pid); }
async function loadLog(pid){ const j=await fetchJson('/api/projects/'+enc(pid)+'/log'); qs('logBox').innerHTML = `<pre>${esc(j.tail || '')}</pre>`; }

function renderProfile(){ const p=S.prefs||{}; qs('page-profile').innerHTML = `<div class="card"><h2>User profile + attack controls</h2><p class="sub">These defaults are applied to new projects. Project settings can override them.</p><div class="grid"><label>profile<input id="prefName" value="${esc(p.profile_name||'Operator')}"></label><label>theme<select id="prefTheme"><option ${p.theme==='dark'?'selected':''}>dark</option><option ${p.theme==='light'?'selected':''}>light</option><option ${p.theme==='system'?'selected':''}>system</option></select></label><label>accent<input id="prefAccent" value="${esc(p.accent_color||'#35d07f')}"></label><label>tool color<input id="prefTool" value="${esc(p.tool_color||'#35d07f')}"></label></div><br>${settingsFormHtml('pref', p)}<label class="pill"><input type="checkbox" id="prefCounter" ${p.show_project_counter===false?'':'checked'}> show project counter</label><br><br><button class="btn primary" onclick="saveProfile()">Save profile</button><pre>${esc(JSON.stringify(p,null,2))}</pre></div>`; }
async function saveProfile(){ const st=readSettings('pref'); st.profile_name=qs('prefName').value; st.theme=qs('prefTheme').value; st.accent_color=qs('prefAccent').value; st.tool_color=qs('prefTool').value; st.show_project_counter=qs('prefCounter').checked; const j=await fetchJson('/api/preferences',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(st)}); if(!j.ok) alert(j.error||'save failed'); await loadPreferences(); renderProfile(); renderCreate(); }
async function loadTools(){ const j=await fetchJson('/api/tool_status'); const rows=(j.tools||[]).map(t=>`<div class="find"><div class="row between"><b>${esc(t.name)}</b><span class="pill ${t.installed?'ok':'bad'}">${t.installed?'installed':'missing'}</span></div><p class="sub">deps: ${esc((t.deps||[]).join(', ')||'none')} ${t.missing?.length?' · missing: '+esc(t.missing.join(', ')):''}</p></div>`).join(''); qs('page-tools').innerHTML = `<div class="card"><div class="row between"><h2>Tool status</h2><button class="btn" onclick="loadTools()">Refresh</button></div>${rows || '<p class="warn">No tool status.</p>'}</div>`; }
