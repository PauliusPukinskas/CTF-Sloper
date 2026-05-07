'use strict';

const S = {
  prefs: null, projects: [], current: null,
  activePage: 'create', activeTab: 'overview',
  projectView: 'list',   // 'list' | 'detail'
  sideProjOpen: false,
  files: [], poller: null, lastJobStatus: '', openingPid: null
};
const tabs = [
  ['overview', 'Overview'], ['flags', 'Flags'], ['artifacts', 'Artifacts'], ['files', 'Files'],
  ['logs', 'Logs'], ['settings', 'Settings'], ['tools', 'Manual tools']
];
const fileTools = ['strings', 'exiftool', 'binwalk', 'foremost', 'zsteg', 'steghide_info', 'tshark_quick', 'file', 'xxd_head'];

function qs(id){ return document.getElementById(id); }
function numInput(id, min, max, val, step){ const s=step||1; return `<div class="stepper"><button type="button" class="stepper-btn" onclick="stepNum('${id}',-${s},${min},${max})">−</button><input id="${id}" type="number" min="${min}" max="${max}" value="${esc(val)}"><button type="button" class="stepper-btn" onclick="stepNum('${id}',${s},${min},${max})">+</button></div>`; }
function stepNum(id, dir, min, max){ const el=qs(id); if(!el) return; let v=Number(el.value)+dir; if(v<min) v=min; if(v>max) v=max; el.value=v; }
function esc(x){ return String(x ?? '').replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function enc(x){ return encodeURIComponent(String(x ?? '')); }
async function fetchJson(url, opts){ const r=await fetch(url,opts||{}); const t=await r.text(); try{return JSON.parse(t);}catch(e){return{ok:false,error:t||String(e),status:r.status};} }
function copyText(x){ navigator.clipboard?.writeText(String(x)).catch(()=>{}); }
function hashStr(s){ let h=5381,n=Math.min(s.length,10000); for(let i=0;i<n;i++) h=((h<<5)+h+s.charCodeAt(i))|0; return h; }

// ── Navigation ──────────────────────────────────────────────────────────────

function switchPage(name){
  S.activePage = name;
  document.querySelectorAll('.page').forEach(p=>p.classList.add('hidden'));
  qs('page-'+name)?.classList.remove('hidden');
  document.querySelectorAll('.nav button').forEach(b=>b.classList.remove('on'));
  qs('nav-'+name)?.classList.add('on');
}

function showPage(name){
  switchPage(name);
  if(name === 'projects'){
    if(S.projectView === 'detail' && S.current){
      // Restore detail view if panel was lost (e.g. navigated away and back)
      if(!qs('proj-tab-content')) renderProjectPanel();
    } else {
      loadProjects();
    }
  }
  if(name === 'profile') renderProfile();
  if(name === 'tools') loadTools();
}

// ── Init ────────────────────────────────────────────────────────────────────

async function init(){
  switchPage('create');
  renderCreate();
  renderProfile();
  await loadPreferences();
  renderCreate();    // re-render with saved prefs
  renderProfile();
  await loadProjects();
}
document.addEventListener('DOMContentLoaded', init);

// ── Preferences ─────────────────────────────────────────────────────────────

async function loadPreferences(){
  const j = await fetchJson('/api/preferences');
  S.prefs = j.preferences || {};
  S.formats = j.formats || {};
  S.attackPresets = j.attack_presets || {};
  S.difficulties = j.difficulties || ['easy','medium','hard','multi_step'];
  S.categories = j.categories || [];
  const total = j.project_counter?.total ?? 0;
  qs('sideStats').innerHTML = `<p>Projects: <b>${esc(total)}</b></p><p>Default: <b>${esc(S.prefs.flag_label||S.prefs.flag_format||'ctf_cs')}</b></p><p>Preset: <b>${esc(S.prefs.attack_preset||'balanced')}</b></p>`;
}
function formatOptions(selected){
  const entries = Object.entries(S.formats||{ctf_cs:{label:'ctf_cs{...}'},ctf_cm:{label:'ctf_cm{...}'},flag:{label:'flag{...}'},any_prefix:{label:'anyPrefix{...}'},braces_only:{label:'{...}'},custom_regex:{label:'custom regex'}});
  return entries.map(([k,v])=>`<option value="${esc(k)}" ${selected===k?'selected':''}>${esc(v.label||k)}</option>`).join('');
}
function presetOptions(selected){ return Object.keys(S.attackPresets||{quick:1,balanced:1,deep:1,hardcore:1}).map(k=>`<option value="${esc(k)}" ${selected===k?'selected':''}>${esc(k)}</option>`).join(''); }
function difficultyOptions(selected){ return (S.difficulties||['easy','medium','hard','multi_step']).map(k=>`<option value="${esc(k)}" ${selected===k?'selected':''}>${esc(k.replace('_','-'))}</option>`).join(''); }

// ── Create page ──────────────────────────────────────────────────────────────

function renderCreate(){
  const p = S.prefs || {};
  qs('page-create').innerHTML = `<div class="card"><h2>Create challenge project</h2><p class="sub">Upload challenge files, choose the expected flag wrapper and how aggressively Sloper should decode/chain artifacts.</p>
  <div id="drop" class="drop"><b>Drop files or ZIP here</b><br><br><button class="btn primary" onclick="qs('fileInput').click()">Select files</button><input id="fileInput" class="fileInput" type="file" multiple onchange="setFiles(this.files)"><div id="fileCount" class="sub">No files selected</div></div>
  <br><div class="grid"><label>Title<input id="title" placeholder="challenge name"></label><label>Category<select id="category"><option value="auto">auto</option><option>crypto</option><option>stego</option><option>forensics</option><option>reversing</option><option>web</option><option>osint</option><option>misc</option></select></label></div>
  <br><textarea id="statement" placeholder="Task statement / hint / flag format text"></textarea><br><br>
  ${settingsFormHtml('create', p)}
  <div class="row"><label class="pill"><input type="checkbox" id="autoStart" checked> auto start</label><button class="btn primary" onclick="createProject()">Create + Solve</button><span class="pill">bounded multi-step</span></div></div>`;
  const drop = qs('drop');
  drop.ondragover = ev=>{ev.preventDefault();drop.style.borderColor='var(--accent)';};
  drop.ondragleave = ()=>{drop.style.borderColor='var(--line)';};
  drop.ondrop = ev=>{ev.preventDefault();drop.style.borderColor='var(--line)';setFiles(ev.dataTransfer.files);};
}
function settingsFormHtml(prefix, p){
  return `<div class="grid"><label>flag format<select id="${prefix}FlagFormat">${formatOptions(p.flag_format||'ctf_cs')}</select></label><label>custom regex<input id="${prefix}CustomRegex" value="${esc(p.custom_flag_regex||'')}" placeholder="KEY-[A-Z0-9-]+"></label><label>attack preset<select id="${prefix}AttackPreset">${presetOptions(p.attack_preset||'balanced')}</select></label><label>difficulty<select id="${prefix}Difficulty">${difficultyOptions(p.difficulty||'medium')}</select></label><label>max depth${numInput(prefix+'MaxDepth',0,10,p.max_depth??2)}</label><label>max artifacts${numInput(prefix+'MaxArtifacts',50,15000,p.max_artifacts??800,100)}</label></div><br>`;
}
function readSettings(prefix){
  const ff = qs(prefix+'FlagFormat')?.value||'ctf_cs';
  const prefixMap = {ctf_cs:'ctf_cs',ctf_cm:'ctf_cm',flag:'flag',picoctf:'picoCTF',htb:'HTB'};
  return {flag_format:ff,flag_prefix:prefixMap[ff]||(S.prefs?.flag_prefix||'ctf_cs'),custom_flag_regex:qs(prefix+'CustomRegex')?.value||'',attack_preset:qs(prefix+'AttackPreset')?.value||'balanced',difficulty:qs(prefix+'Difficulty')?.value||'medium',max_depth:Number(qs(prefix+'MaxDepth')?.value||2),max_artifacts:Number(qs(prefix+'MaxArtifacts')?.value||800)};
}
function setFiles(list){ S.files=Array.from(list||[]); qs('fileCount').textContent=S.files.length?S.files.map(f=>f.name).join(', '):'No files selected'; if(!qs('title').value&&S.files[0]) qs('title').value=S.files[0].name; }

async function createProject(){
  if(!S.files.length){ alert('Add files first'); return; }
  const fd = new FormData(); S.files.forEach(f=>fd.append('files',f));
  fd.append('title',qs('title').value||S.files[0].name); fd.append('statement',qs('statement').value||''); fd.append('category',qs('category').value||'auto'); fd.append('auto_start',qs('autoStart').checked?'true':'false');
  const st = readSettings('create'); Object.entries(st).forEach(([k,v])=>fd.append(k,String(v)));
  const j = await fetchJson('/api/projects',{method:'POST',body:fd});
  if(!j.ok){ alert(j.error||'create failed'); return; }
  await loadProjects();
  await openProject(j.id);  // openProject handles switchPage itself
}

// ── Projects list loading ────────────────────────────────────────────────────

async function loadProjects(){
  const j = await fetchJson('/api/projects');
  S.projects = j.projects || [];
  updateSideProjects();
  // Only re-render the list if we're currently in list view on the projects page
  if(S.activePage === 'projects' && S.projectView === 'list') showProjectsList();
  await loadPreferences();
}

// ── Projects list view (full page) ──────────────────────────────────────────

function showProjectsList(){
  S.projectView = 'list';
  const cards = S.projects.map(p=>{
    const running = p.runtime_status === 'running';
    const done = p.runtime_status === 'done';
    const statusColor = running ? 'var(--accent)' : done ? 'var(--ok)' : 'var(--muted)';
    const statusLabel = running ? '<span class="running-dot" style="color:var(--accent)">●</span> running' : done ? '<span style="color:var(--ok)">✓</span> done' : esc(p.runtime_status||'idle');
    return `<div class="card" style="cursor:pointer;transition:border-color .15s" onmouseenter="this.style.borderColor='var(--accent)'" onmouseleave="this.style.borderColor=''" onclick="openProject('${esc(p.id)}')">
      <div class="row between">
        <div style="min-width:0">
          <b style="font-size:15px">${esc(p.title||p.id)}</b>
          <div class="sub" style="margin-top:2px">${esc(p.category||'misc')}</div>
        </div>
        <div style="text-align:right;flex-shrink:0">
          <div class="sub" style="color:${statusColor}">${statusLabel}</div>
          <div class="sub" style="margin-top:2px">${esc(p.progress??0)}%</div>
        </div>
      </div>
    </div>`;
  }).join('') || '<div class="card"><p class="warn">No projects yet — create one first.</p></div>';

  qs('page-projects').innerHTML = `<div class="card" style="margin-bottom:16px"><div class="row between"><h2 style="margin:0">Projects</h2><button class="btn" onclick="loadProjects()">↻ Refresh</button></div></div><div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(260px,1fr))">${cards}</div>`;
}

// ── Project detail view ──────────────────────────────────────────────────────

// Renders a full-width project detail panel with a back button into page-projects
function renderProjectPanel(){
  if(!S.current){ showProjectsList(); return; }
  qs('page-projects').innerHTML = `<div style="margin-bottom:14px"><button class="btn" onclick="backToProjectList()" style="gap:6px">← All projects</button></div>${projectHtml(S.current)}`;
}

function backToProjectList(){
  clearInterval(S.poller);
  S.projectView = 'list';
  switchPage('projects');
  showProjectsList();
  updateSideProjects();
}

// ── Open a specific project ──────────────────────────────────────────────────

async function openProject(pid){
  const isNew = S.current?.project?.id !== pid;
  S.openingPid = pid;
  S.projectView = 'detail';
  switchPage('projects');

  if(isNew){
    S.activeTab = 'overview';
    qs('page-projects').innerHTML = `<div style="margin-bottom:14px"><button class="btn" onclick="backToProjectList()">← All projects</button></div><div class="card"><p class="sub">Loading…</p></div>`;
  }

  const j = await fetchJson('/api/projects/'+enc(pid));
  if(S.openingPid !== pid) return;   // superseded
  S.current = j;
  S.lastJobStatus = j.job?.status || '';
  renderProjectPanel();
  updateSideProjects();
  pollProject(pid);
}

// ── Polling ──────────────────────────────────────────────────────────────────

function pollProject(pid){
  clearInterval(S.poller);
  let busy = false;
  S.poller = setInterval(async()=>{
    if(busy || S.current?.project?.id !== pid || !qs('proj-tab-content')) return;
    busy = true;
    try {
      const j = await fetchJson('/api/projects/'+enc(pid));
      if(S.current?.project?.id !== pid){ busy=false; return; }
      S.current = j;
      const newStatus = j.job?.status || '';
      // Only snap back to overview when the job actually finishes
      if(S.lastJobStatus !== 'done' && newStatus === 'done') S.activeTab = 'overview';
      S.lastJobStatus = newStatus;
      updateProjectPanel(j);
      updateSideProjects();
      if(['done','error','cancelled'].includes(newStatus)) clearInterval(S.poller);
    } finally { busy = false; }
  }, 1000);
}

// ── Tab switching ────────────────────────────────────────────────────────────

function setTab(t){
  S.activeTab = t;
  if(S.current) updateProjectPanel(S.current);
}

// ── Project HTML (stable structure with targetable IDs) ──────────────────────

function projectHtml(j){
  const meta=j.project||{}, job=j.job||{}, rep=j.report||{}, sum=rep.summary||{}, files=rep.files||[];
  const running = job.status === 'running';
  const tabButtons = tabs.map(([id,label])=>`<button class="btn ${S.activeTab===id?'primary':''}" id="tab-btn-${id}" onclick="setTab('${id}')">${esc(label)}</button>`).join('');
  return `<div class="card"><div class="row between"><div><h2>${esc(meta.title||'Project')}</h2><div class="sub">${esc(meta.id||'')} · ${esc(meta.category||'')} · ${esc(sum.preferred_flag_format||'')}</div></div><div class="row"><button class="btn primary" onclick="startProject('${esc(meta.id||'')}')">Start</button><button class="btn danger" onclick="stopProject('${esc(meta.id||'')}')">Stop</button></div></div><div id="proj-metrics">${metricsHtml(sum,files,job)}</div><div class="progress"><div class="bar${running?' running':''}" id="proj-bar" style="${running?'':('width:'+Number(job.progress||0)+'%')}"></div></div><p class="sub" id="proj-stage">${stageHtml(job)}</p></div><div class="card"><div class="tabs">${tabButtons}</div><div id="proj-tab-content">${tabHtml(S.activeTab,meta,sum,files,j)}</div></div>`;
}

function stageHtml(job){
  const s = job.status || '';
  const t = esc(job.stage || '');
  if(s === 'running') return `<span class="running-dot" style="color:var(--accent)">●</span> ${t||'Running…'}`;
  if(s === 'done')    return `<span style="color:var(--ok)">✓</span> ${t||'Done'}`;
  if(s === 'error')   return `<span style="color:var(--bad)">✗</span> ${t||'Error'}`;
  return t;
}

// ── Targeted in-place update (called every poll tick) ────────────────────────

function updateProjectPanel(j){
  const meta=j.project||{}, job=j.job||{}, rep=j.report||{}, sum=rep.summary||{}, files=rep.files||[];
  const running = job.status === 'running';

  // Progress bar — animated while running, width-based otherwise
  const bar = qs('proj-bar');
  if(bar){
    if(running){
      bar.className = 'bar running';
      bar.style.width = '';
    } else {
      bar.className = 'bar';
      bar.style.width = Number(job.progress||0)+'%';
    }
  }

  // Stage text with status icon
  const stage = qs('proj-stage');
  if(stage) stage.innerHTML = stageHtml(job);

  // Metrics grid
  const metrics = qs('proj-metrics');
  if(metrics) metrics.innerHTML = metricsHtml(sum,files,job);

  // Tab content — only replace DOM if HTML actually changed (preserves expanded artifact views)
  const content = qs('proj-tab-content');
  if(content){
    const html = tabHtml(S.activeTab,meta,sum,files,j);
    const h = String(hashStr(html));
    if(content.dataset.h !== h){ content.innerHTML=html; content.dataset.h=h; }
  }

  // Tab button active states
  tabs.forEach(([id])=>{ const b=qs('tab-btn-'+id); if(b) b.className='btn'+(S.activeTab===id?' primary':''); });
}

// ── Sidebar project picker ───────────────────────────────────────────────────

function updateSideProjects(){
  const wrap = qs('side-proj-wrap');
  if(!wrap) return;
  if(!S.projects.length){ wrap.innerHTML=''; return; }

  const curId = S.current?.project?.id;
  const active = S.projects.find(p=>p.id===curId);

  // Header button — shows active project name or "Select project…"
  const headerLabel = active
    ? `<span style="display:flex;align-items:center;gap:6px;min-width:0"><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">${active.runtime_status==='running'?`<span class="running-dot" style="color:var(--accent)">●</span> `:active.runtime_status==='done'?'<span style="color:var(--ok)">✓</span> ':''}${esc(active.title||active.id)}</span></span>`
    : `<span style="color:var(--muted)">Select project…</span>`;

  const arrow = S.sideProjOpen ? '▲' : '▼';

  const dropdown = S.sideProjOpen ? `<div style="background:#020906;border:1px solid var(--line);border-top:none;border-radius:0 0 10px 10px;max-height:240px;overflow-y:auto;padding:4px 4px 6px">${
    S.projects.map(p=>{
      const running = p.runtime_status === 'running';
      const done = p.runtime_status === 'done';
      const isCur = p.id === curId;
      return `<button class="side-proj-btn${isCur?' active-proj':''}" onclick="pickSideProject('${esc(p.id)}')">
        <span style="font-size:13px;font-weight:${isCur?700:400}">${running?`<span class="running-dot" style="color:var(--accent)">● </span>`:done?'<span style="color:var(--ok)">✓ </span>':''}${esc(p.title||p.id)}</span>
        <span class="sub" style="display:block;font-size:10px;margin-top:1px">${running?'running':done?'done':esc(p.runtime_status||'idle')} · ${esc(p.progress??0)}%</span>
      </button>`;
    }).join('')
  }</div>` : '';

  wrap.innerHTML = `<div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--line)">
    <button onclick="toggleSideProjects()" style="display:flex;align-items:center;justify-content:space-between;width:100%;padding:7px 10px;background:#082416;border:1px solid var(--line);border-radius:${S.sideProjOpen?'10px 10px 0 0':'10px'};cursor:pointer;color:var(--text);font-size:13px;gap:6px">
      <span style="flex:1;min-width:0;overflow:hidden">${headerLabel}</span>
      <span style="color:var(--muted);flex-shrink:0;font-size:11px">${arrow}</span>
    </button>
    ${dropdown}
  </div>`;
}

function toggleSideProjects(){
  S.sideProjOpen = !S.sideProjOpen;
  updateSideProjects();
}

function pickSideProject(pid){
  S.sideProjOpen = false;
  openProject(pid);
}

// ── Metrics & tab rendering ──────────────────────────────────────────────────

function metricsHtml(sum, files, job){ return `<div class="grid"><div class="metric"><b>${esc(job.progress??0)}%</b><div class="sub">progress</div></div><div class="metric"><b>${files.length}</b><div class="sub">files</div></div><div class="metric"><b>${(sum.flags||[]).length}</b><div class="sub">promoted flags</div></div><div class="metric"><b>${(sum.related_candidate_flags||[]).length}</b><div class="sub">related candidates</div></div><div class="metric"><b>${(sum.artifacts||[]).length}</b><div class="sub">artifacts</div></div><div class="metric"><b>${esc(sum.v115_triage?.version||sum.v114_triage?.version||sum.v113_evidence?.version||sum.v110_fast_summary?.version||'fast')}</b><div class="sub">engine</div></div><div class="metric"><b>${esc(sum.v115_triage?.best_score??sum.v114_triage?.best_confidence??sum.v113_evidence?.promoted??0)}</b><div class="sub">best confidence</div></div><div class="metric"><b>${esc(sum.v115_triage?.trusted??sum.v114_triage?.high_confidence??0)}</b><div class="sub">high confidence</div></div></div><br>`; }
function tabHtml(tab, meta, sum, files, j){
  if(tab==='flags') return flagsHtml(sum);
  if(tab==='artifacts') return artifactsHtml(sum.artifacts||[]);
  if(tab==='files') return filesHtml(files);
  if(tab==='logs') return `<button class="btn" onclick="loadLog('${esc(meta.id)}')">Refresh log</button><div id="logBox"><pre>${esc(j.log||'')}</pre></div>`;
  if(tab==='settings') return projectSettingsHtml(meta);
  if(tab==='tools') return manualToolsHtml(files);
  return overviewHtml(sum);
}
function triageHtml(sum){ const v=sum.v115_triage||null; const t=v||sum.v114_triage||{}; if(v) return `<div class="find"><b>v115 live competition triage</b><p class="sub">best: ${esc(v.best_flag||'none')} · score ${esc(v.best_score||0)} · trusted ${esc(v.trusted||0)} · promising ${esc(v.promising||0)} · manual ${esc(v.manual_review||0)}</p><p class="sub">source: ${esc(v.best_source||'')} · priority artifacts ${esc(v.priority_artifacts||0)}</p><p class="sub">${esc(v.operator_hint||'')}</p></div>`; return `<div class="find"><b>v114 operator triage</b><p class="sub">best: ${esc(t.best_flag||'none')} · confidence ${esc(t.best_confidence||0)}% · high ${esc(t.high_confidence||0)} · medium ${esc(t.medium_confidence||0)} · related ${esc(t.low_or_related||0)}</p><p class="sub">${esc(t.operator_hint||'')}</p></div>`; }
function overviewHtml(sum){ return `${triageHtml(sum)}<h3>Best flags</h3>${flagsHtml(sum,8)}<h3>Clean artifact queue</h3>${artifactsHtml((sum.artifacts||[]).slice(0,12))}`; }
function flagsHtml(sum, limit){ const flags=(sum.flags||[]).slice(0,limit||120); const related=(sum.related_candidate_flags||[]).slice(0,30); return `${flags.map(f=>flagRow(f)).join('')||'<p class="warn">No promoted flag yet.</p>'}${related.length?'<h3>Related candidates</h3>'+related.map(f=>flagRow(f,true)).join(''):''}`; }
function flagRow(f, weak){ const val=f.preferred_flag||f.flag||f.value||''; const conf=f.confidence??''; const risk=f.risk??''; const verdict=f.verdict||(weak?'related':'promoted'); const chain=f.chain_text||(Array.isArray(f.chain)?f.chain.join(' → '):f.source||''); const why=Array.isArray(f.why)?f.why.join(', '):(f.why||''); const warn=Array.isArray(f.warnings)?f.warnings.join(', '):(f.warnings||''); return `<div class="flag"><div class="row between"><b class="${weak?'warn':'ok'}">${esc(val)}</b><button class="btn" onclick="copyText('${esc(val)}')">copy</button></div><div class="row"><span class="pill">${esc(verdict)}</span>${conf!==''?`<span class="pill">confidence ${esc(conf)}%</span>`:''}${risk!==''?`<span class="pill">risk ${esc(risk)}%</span>`:''}<span class="pill">score ${esc(f.score||f.rank_score||0)}</span></div><div class="sub">${esc(f.file||'')} · ${esc(chain)}</div>${why?`<div class="sub ok">why: ${esc(why)}</div>`:''}${warn?`<div class="sub warn">warn: ${esc(warn)}</div>`:''}</div>`; }
function artifactsHtml(items){ if(!items.length) return '<p class="warn">No artifacts yet.</p>'; return items.map((a,i)=>{ const uid=`artv_${i}`; return `<div class="find artifact"><div><span class="score">${esc(a.score||0)}</span><br><span class="pill">${esc(a.kind||'artifact')}</span></div><div style="min-width:0"><b>${esc(a.name||a.path||a.url||'artifact')}</b><p class="sub">${esc(a.source||'')} · ${esc(a.file||'')} · ${esc(a.note||'')}</p><div id="${uid}"></div></div><div class="row">${a.path?`<button class="btn" onclick="viewArtifact('${enc(a.path)}','${uid}')">view</button>`:''}</div></div>`; }).join(''); }
async function viewArtifact(path, uid){ const el=qs(uid); if(!el) return; if(el.dataset.open==='1'){el.innerHTML='';el.dataset.open='0';return;} el.innerHTML='<span class="sub">loading…</span>'; try{ const r=await fetch('/api/raw?path='+path); const t=await r.text(); el.innerHTML=`<pre>${esc(t.slice(0,12000))}${t.length>12000?'\n… (truncated)':''}</pre>`; el.dataset.open='1'; }catch(e){ el.innerHTML=`<span class="bad">${esc(String(e))}</span>`; } }
function filesHtml(files){ return files.map(f=>`<div class="find"><div class="row between"><div><b>${esc(f.rel||f.name)}</b><div class="sub">${esc(f.kind||'')} · ${esc(f.size||0)} bytes</div></div><div class="row"><button class="btn" onclick="previewFile('${enc(f.path)}')">preview</button>${f.path?`<a class="btn" target="_blank" href="/api/raw?path=${enc(f.path)}">raw</a>`:''}</div></div><div id="preview-${esc(f.path||f.name)}"></div></div>`).join('')||'<p class="warn">No files.</p>'; }
async function previewFile(path){ const j=await fetchJson('/api/raw_info?path='+path); alert(JSON.stringify(j,null,2)); }
function projectSettingsHtml(meta){ const p=meta.solver_settings||S.prefs||{}; return `<h3>Project solver settings</h3>${settingsFormHtml('project',p)}<button class="btn primary" onclick="saveProjectSettings('${esc(meta.id)}')">Save project settings</button><pre>${esc(JSON.stringify(p,null,2))}</pre>`; }
async function saveProjectSettings(pid){
  const st=readSettings('project');
  const j=await fetchJson('/api/projects/'+enc(pid)+'/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(st)});
  if(!j.ok){alert(j.error||'failed');return;}
  const pj=await fetchJson('/api/projects/'+enc(pid));
  S.current=pj;
  renderProjectPanel();
}
function manualToolsHtml(files){ const options=files.map(f=>`<option value="${esc(f.path||'')}">${esc(f.rel||f.name)}</option>`).join(''); return `<label>file<select id="toolFile">${options}</select></label><br><label>tool<select id="toolName">${fileTools.map(t=>`<option>${esc(t)}</option>`).join('')}</select></label><br><button class="btn primary" onclick="runTool()">Run tool</button><div id="toolOut"></div>`; }
async function runTool(){ const path=qs('toolFile').value, tool=qs('toolName').value; const j=await fetchJson('/api/run_tool',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path,tool})}); qs('toolOut').innerHTML=`<pre>${esc(JSON.stringify(j,null,2))}</pre>`; }

// ── Project controls ─────────────────────────────────────────────────────────

async function startProject(pid){
  // Immediate visual feedback — no waiting for API
  const bar = qs('proj-bar');
  if(bar){ bar.className='bar running'; bar.style.width=''; }
  const stage = qs('proj-stage');
  if(stage) stage.innerHTML = '<span class="running-dot" style="color:var(--accent)">●</span> Starting…';

  await fetchJson('/api/projects/'+enc(pid)+'/start',{method:'POST'});
  S.lastJobStatus = '';
  pollProject(pid);
}
async function stopProject(pid){ await fetchJson('/api/projects/'+enc(pid)+'/stop',{method:'POST'}); }
async function loadLog(pid){ const j=await fetchJson('/api/projects/'+enc(pid)+'/log'); const box=qs('logBox'); if(box) box.innerHTML=`<pre>${esc(j.tail||j.log||'')}</pre>`; }

// ── Profile ──────────────────────────────────────────────────────────────────

function renderProfile(){ const p=S.prefs||{}; qs('page-profile').innerHTML=`<div class="card"><h2>User profile + attack controls</h2><p class="sub">These defaults are applied to new projects. Project settings can override them.</p><div class="grid"><label>profile<input id="prefName" value="${esc(p.profile_name||'Operator')}"></label><label>theme<select id="prefTheme"><option ${p.theme==='dark'?'selected':''}>dark</option><option ${p.theme==='light'?'selected':''}>light</option><option ${p.theme==='system'?'selected':''}>system</option></select></label><label>accent<input id="prefAccent" value="${esc(p.accent_color||'#35d07f')}"></label><label>tool color<input id="prefTool" value="${esc(p.tool_color||'#35d07f')}"></label></div><br>${settingsFormHtml('pref',p)}<label class="pill"><input type="checkbox" id="prefCounter" ${p.show_project_counter===false?'':'checked'}> show project counter</label><br><br><button class="btn primary" onclick="saveProfile()">Save profile</button><pre>${esc(JSON.stringify(p,null,2))}</pre></div>`; }
async function saveProfile(){ const st=readSettings('pref'); st.profile_name=qs('prefName').value; st.theme=qs('prefTheme').value; st.accent_color=qs('prefAccent').value; st.tool_color=qs('prefTool').value; st.show_project_counter=qs('prefCounter').checked; const j=await fetchJson('/api/preferences',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(st)}); if(!j.ok) alert(j.error||'save failed'); await loadPreferences(); renderProfile(); renderCreate(); }
async function loadTools(){ const j=await fetchJson('/api/tool_status'); const rows=(j.tools||[]).map(t=>`<div class="find"><div class="row between"><b>${esc(t.name)}</b><span class="pill ${t.installed?'ok':'bad'}">${t.installed?'installed':'missing'}</span></div><p class="sub">deps: ${esc((t.deps||[]).join(', ')||'none')} ${t.missing?.length?' · missing: '+esc(t.missing.join(', ')):''}</p></div>`).join(''); qs('page-tools').innerHTML=`<div class="card"><div class="row between"><h2>Tool status</h2><button class="btn" onclick="loadTools()">Refresh</button></div>${rows||'<p class="warn">No tool status.</p>'}</div>`; }
