'use strict';

const S = {
  prefs: null, projects: [], current: null,
  activePage: 'create', activeTab: 'overview',
  projectView: 'list',   // 'list' | 'detail'
  sideProjOpen: false,
  files: [], poller: null, lastJobStatus: '', openingPid: null
};
const tabs = [
  ['overview', 'Overview'], ['flags', 'Flags'], ['artifacts', 'Artifacts'], ['visuals', 'Visuals'],
  ['files', 'Files'], ['logs', 'Logs'], ['settings', 'Settings'], ['tools', 'Manual tools']
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
const artifactCache = new Map();

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
  <div id="drop" class="drop"><b>Drop files or ZIP here</b><br><br><button class="btn primary" onclick="qs('fileInput').click()">Add files</button><input id="fileInput" class="fileInput" type="file" multiple onchange="addFiles(this.files);this.value=''"><div id="fileList"></div></div>
  <br><div class="grid"><label>Title<input id="title" placeholder="challenge name"></label><label>Category<select id="category"><option value="auto">auto</option><option>crypto</option><option>stego</option><option>forensics</option><option>reversing</option><option>web</option><option>osint</option><option>misc</option></select></label></div>
  <br><textarea id="statement" placeholder="Task statement / hint / flag format text"></textarea><br><br>
  ${settingsFormHtml('create', p)}
  <div class="row"><label class="pill"><input type="checkbox" id="autoStart" checked> auto start</label><button class="btn primary" onclick="createProject()">Create + Solve</button></div></div>`;
  const drop = qs('drop');
  drop.ondragover = ev=>{ev.preventDefault();drop.style.borderColor='var(--accent)';};
  drop.ondragleave = ()=>{drop.style.borderColor='var(--line)';};
  drop.ondrop = ev=>{ev.preventDefault();drop.style.borderColor='var(--line)';addFiles(ev.dataTransfer.files);};
  renderFileList();
}
function settingsFormHtml(prefix, p){
  return `<div class="grid"><label>flag format<select id="${prefix}FlagFormat">${formatOptions(p.flag_format||'ctf_cs')}</select></label><label>custom regex<input id="${prefix}CustomRegex" value="${esc(p.custom_flag_regex||'')}" placeholder="KEY-[A-Z0-9-]+"></label><label>attack preset<select id="${prefix}AttackPreset">${presetOptions(p.attack_preset||'balanced')}</select></label><label>difficulty<select id="${prefix}Difficulty">${difficultyOptions(p.difficulty||'medium')}</select></label><label>max depth${numInput(prefix+'MaxDepth',0,10,p.max_depth??2)}</label><label>max artifacts${numInput(prefix+'MaxArtifacts',50,15000,p.max_artifacts??800,100)}</label></div><br>`;
}
function readSettings(prefix){
  const ff = qs(prefix+'FlagFormat')?.value||'ctf_cs';
  const prefixMap = {ctf_cs:'ctf_cs',ctf_cm:'ctf_cm',flag:'flag',picoctf:'picoCTF',htb:'HTB'};
  return {flag_format:ff,flag_prefix:prefixMap[ff]||(S.prefs?.flag_prefix||'ctf_cs'),custom_flag_regex:qs(prefix+'CustomRegex')?.value||'',attack_preset:qs(prefix+'AttackPreset')?.value||'balanced',difficulty:qs(prefix+'Difficulty')?.value||'medium',max_depth:Number(qs(prefix+'MaxDepth')?.value||2),max_artifacts:Number(qs(prefix+'MaxArtifacts')?.value||800)};
}
function addFiles(list){
  const wasEmpty = !S.files.length;
  Array.from(list||[]).forEach(f=>S.files.push(f));
  renderFileList();
  if(wasEmpty && S.files[0] && !qs('title')?.value) qs('title').value=S.files[0].name;
}
function removeFile(i){ S.files.splice(i,1); renderFileList(); }
function clearFiles(){ S.files=[]; renderFileList(); }
function renderFileList(){
  const el=qs('fileList'); if(!el) return;
  if(!S.files.length){ el.innerHTML='<div style="padding:10px 0 2px;display:flex;align-items:center;justify-content:center"><span class="sub">No files selected</span></div>'; return; }
  const chips=S.files.map((f,i)=>`<div style="display:inline-flex;align-items:stretch;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:#06170e;max-width:280px"><span style="padding:7px 11px;font-size:13px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:flex;align-items:center" title="${esc(f.name)}">${esc(f.name)}</span><button style="border:none;border-left:1px solid var(--line);background:transparent;color:var(--muted);cursor:pointer;width:30px;font-size:17px;font-weight:700;flex-shrink:0;display:flex;align-items:center;justify-content:center;padding:0" onmouseover="this.style.color='var(--bad)'" onmouseout="this.style.color='var(--muted)'" onclick="removeFile(${i})">×</button></div>`).join('');
  el.innerHTML=`<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:18px;justify-content:center">${chips}</div><div style="margin-top:14px;text-align:center"><button class="btn" onclick="clearFiles()">Clear all</button></div>`;
}

async function createProject(){
  if(!S.files.length){ alert('Add files first'); return; }
  const fd = new FormData(); S.files.forEach(f=>fd.append('files',f));
  fd.append('title',qs('title').value||S.files[0].name); fd.append('statement',qs('statement').value||''); fd.append('category',qs('category').value||'auto'); fd.append('auto_start',qs('autoStart').checked?'true':'false');
  const st = readSettings('create'); Object.entries(st).forEach(([k,v])=>fd.append(k,String(v)));
  const j = await fetchJson('/api/projects',{method:'POST',body:fd});
  if(!j.ok){ alert(j.error||'create failed'); return; }
  S.files=[];
  renderCreate();
  await loadProjects();
  await openProject(j.id);
}

// ── Projects list loading ────────────────────────────────────────────────────

async function loadProjects(){
  const j = await fetchJson('/api/projects_meta');
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

function othersBarHtml(){
  if(!S.projects.length) return '';
  const curId = S.current?.project?.id;
  const curJob = S.current?.job || {};
  return S.projects.map(p=>{
    const isCur = p.id === curId;
    const pct  = isCur ? Number(curJob.progress ?? p.progress ?? 0) : Number(p.progress ?? 0);
    const st   = isCur ? (curJob.status || p.runtime_status || 'idle') : (p.runtime_status || 'idle');
    const icon = st==='running' ? `<span class="running-dot" style="color:var(--accent)">●</span> `
               : st==='done'    ? `<span style="color:var(--ok)">✓</span> `
               : st==='error'   ? `<span style="color:var(--bad)">✗</span> ` : '';
    const subLabel = st==='running' ? `running · ${pct}%` : st==='done' ? `done · ${pct}%` : esc(st||'idle');
    return `<button class="proj-pill${isCur?' cur-pill':''}" onclick="pickSideProject('${esc(p.id)}')" title="${esc(p.title||p.id)}"><div class="proj-pill-name">${icon}${esc(p.title||p.id)}</div><div class="proj-pill-sub">${subLabel}</div><div class="proj-pill-track"><div class="proj-pill-fill" style="width:${pct}%"></div></div></button>`;
  }).join('');
}

// Renders a full-width project detail panel with a back button into page-projects
function renderProjectPanel(){
  if(!S.current){ showProjectsList(); return; }
  qs('page-projects').innerHTML = `<div style="margin-bottom:14px"><button class="btn" onclick="backToProjectList()">← All projects</button></div><div id="proj-strip-wrap" class="proj-strip">${othersBarHtml()}</div>${projectHtml(S.current)}`;
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

  const j = await fetchJson('/api/projects/'+enc(pid)+'/compact');
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
      const j = await fetchJson('/api/projects/'+enc(pid)+'/compact');
      if(S.current?.project?.id !== pid){ busy=false; return; }
      S.current = j;
      const newStatus = j.job?.status || '';
      // Sync live progress into S.projects so the strip stays accurate
      const pidIdx = S.projects.findIndex(p => p.id === pid);
      if(pidIdx >= 0) Object.assign(S.projects[pidIdx], {progress: j.job?.progress ?? S.projects[pidIdx].progress, runtime_status: newStatus || S.projects[pidIdx].runtime_status});
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

  // Project switcher strip — hash-deduplicated
  const strip = qs('proj-strip-wrap');
  if(strip){
    const sh = String(hashStr(othersBarHtml()));
    if(strip.dataset.h !== sh){ strip.innerHTML = othersBarHtml(); strip.dataset.h = sh; }
  }

  // Tab content — only replace DOM if HTML actually changed (preserves expanded artifact views)
  const content = qs('proj-tab-content');
  if(content){
    const html = tabHtml(S.activeTab,meta,sum,files,j);
    const h = String(hashStr(html));
    if(content.dataset.h !== h){ content.innerHTML=html; content.dataset.h=h; }
  }
  autoLoadArtifacts();

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

function metricsHtml(sum, files, job){ return `<div class="grid"><div class="metric"><b>${esc(job.progress??0)}%</b><div class="sub">progress</div></div><div class="metric"><b>${files.length}</b><div class="sub">files</div></div><div class="metric"><b>${(sum.flags||[]).length}</b><div class="sub">promoted flags</div></div><div class="metric"><b>${(sum.related_candidate_flags||[]).length}</b><div class="sub">related candidates</div></div><div class="metric"><b>${(sum.artifacts||[]).length}</b><div class="sub">artifacts</div></div><div class="metric"><b>${esc(sum.v115_triage?.best_score??sum.v114_triage?.best_confidence??sum.v113_evidence?.promoted??0)}</b><div class="sub">best confidence</div></div><div class="metric"><b>${esc(sum.v115_triage?.trusted??sum.v114_triage?.high_confidence??0)}</b><div class="sub">high confidence</div></div></div><br>`; }
function tabHtml(tab, meta, sum, files, j){
  if(tab==='flags') return flagsHtml(sum);
  if(tab==='artifacts') return artifactsHtml((sum.artifacts||[]).filter(a=>!a.path||!_IMG_EXTS.has(_ext(a.path))));
  if(tab==='visuals') return visualsHtml(sum.artifacts||[]);
  if(tab==='files') return filesHtml(files);
  if(tab==='logs') return `<button class="btn" onclick="loadLog('${esc(meta.id)}')">Refresh log</button><div id="logBox"><pre>${esc(j.log||'')}</pre></div>`;
  if(tab==='settings') return projectSettingsHtml(meta);
  if(tab==='tools') return manualToolsHtml(files);
  return overviewHtml(sum);
}
function triageHtml(sum){ const v=sum.v115_triage||null; const t=v||sum.v114_triage||{}; if(v) return `<div class="find"><b>v115 live competition triage</b><p class="sub">best: ${esc(v.best_flag||'none')} · score ${esc(v.best_score||0)} · trusted ${esc(v.trusted||0)} · promising ${esc(v.promising||0)} · manual ${esc(v.manual_review||0)}</p><p class="sub">source: ${esc(v.best_source||'')} · priority artifacts ${esc(v.priority_artifacts||0)}</p><p class="sub">${esc(v.operator_hint||'')}</p></div>`; return `<div class="find"><b>v114 operator triage</b><p class="sub">best: ${esc(t.best_flag||'none')} · confidence ${esc(t.best_confidence||0)}% · high ${esc(t.high_confidence||0)} · medium ${esc(t.medium_confidence||0)} · related ${esc(t.low_or_related||0)}</p><p class="sub">${esc(t.operator_hint||'')}</p></div>`; }
function overviewHtml(sum){ const nonImg=(sum.artifacts||[]).filter(a=>!a.path||!_IMG_EXTS.has(_ext(a.path))); return `${triageHtml(sum)}<h3>Best flags</h3>${flagsHtml(sum,8)}<h3>Clean artifact queue</h3>${artifactsHtml(nonImg.slice(0,12))}`; }
function flagsHtml(sum, limit){ const flags=(sum.flags||[]).slice(0,limit||120); const related=(sum.related_candidate_flags||[]).slice(0,30); return `${flags.map(f=>flagRow(f)).join('')||'<p class="warn">No promoted flag yet.</p>'}${related.length?'<h3>Related candidates</h3>'+related.map(f=>flagRow(f,true)).join(''):''}`; }
function flagRow(f, weak){ const val=f.preferred_flag||f.flag||f.value||''; const conf=f.confidence??''; const risk=f.risk??''; const verdict=f.verdict||(weak?'related':'promoted'); const chain=f.chain_text||(Array.isArray(f.chain)?f.chain.join(' → '):f.source||''); const why=Array.isArray(f.why)?f.why.join(', '):(f.why||''); const warn=Array.isArray(f.warnings)?f.warnings.join(', '):(f.warnings||''); return `<div class="flag"><div class="row between"><b class="${weak?'warn':'ok'}">${esc(val)}</b><button class="btn" onclick="copyText('${esc(val)}')">copy</button></div><div class="row"><span class="pill">${esc(verdict)}</span>${conf!==''?`<span class="pill">confidence ${esc(conf)}%</span>`:''}${risk!==''?`<span class="pill">risk ${esc(risk)}%</span>`:''}<span class="pill">score ${esc(f.score||f.rank_score||0)}</span></div><div class="sub">${esc(f.file||'')} · ${esc(chain)}</div>${why?`<div class="sub ok">why: ${esc(why)}</div>`:''}${warn?`<div class="sub warn">warn: ${esc(warn)}</div>`:''}</div>`; }
const _IMG_EXTS = new Set(['jpg','jpeg','png','gif','bmp','svg','webp','ico']);
const _TXT_EXTS = new Set(['txt','log','json','xml','html','htm','csv','py','js','ts','sh','md','c','cpp','h','rb','go','rs','yaml','yml','toml','ini','cfg','conf','out','hex']);
function _ext(p){ return (p||'').split('.').pop().toLowerCase(); }
function artifactsHtml(items){
  if(!items.length) return '<p class="warn">No artifacts yet.</p>';
  return items.map((a,i)=>{
    const uid = `artv_${i}`;
    const name = esc(a.name||a.path||a.url||'artifact');
    const meta = [a.source,a.file,a.note].filter(Boolean).map(esc).join(' · ');
    const p = a.path||'';
    const rawUrl = p ? '/api/raw?path='+enc(p) : '';
    let body = '';
    if(p && _IMG_EXTS.has(_ext(p))){
      body = `<img class="preview" src="${rawUrl}" onerror="imgError(this)" data-dl="${rawUrl}" style="max-height:320px">`;
    } else if(p && _TXT_EXTS.has(_ext(p))){
      body = `<div class="artv-text" id="${uid}" data-src="${rawUrl}"><span class="sub">loading…</span></div>`;
    } else if(p){
      body = `<a class="btn" href="${rawUrl}" target="_blank" style="display:inline-block;margin-top:6px">Download</a>`;
    } else if(a.url){
      body = `<a class="btn" href="${esc(a.url)}" target="_blank" style="display:inline-block;margin-top:6px">Open link</a>`;
    }
    return `<div class="find" style="margin:8px 0"><div class="row between" style="gap:6px"><div class="row" style="gap:6px;flex-wrap:wrap;min-width:0"><span class="score">${esc(a.score||0)}</span><span class="pill">${esc(a.kind||'artifact')}</span><b style="word-break:break-all">${name}</b></div><button class="btn" id="art-tog-${uid}" onclick="toggleArtifact('${uid}')" style="flex-shrink:0;padding:4px 9px">▾</button></div>${meta?`<div class="sub" style="margin:3px 0 5px">${meta}</div>`:''}<div id="art-body-${uid}">${body}</div></div>`;
  }).join('');
}
function toggleArtifact(uid){
  const body=document.getElementById('art-body-'+uid), btn=document.getElementById('art-tog-'+uid);
  if(!body) return;
  const hide = body.style.display!=='none';
  body.style.display = hide?'none':'';
  if(btn) btn.textContent = hide?'▸':'▾';
}
function _isPrintable(s){ if(!s||!s.length) return false; let n=0; for(let i=0;i<s.length;i++){const c=s.charCodeAt(i); if(c>=0x20&&c<0x7F) n++;} return n/s.length>0.65; }
function _decodeCard(text, meth, src, quality){
  return `<div style="padding:3px 0;border-bottom:1px solid rgba(128,128,128,.12);font-size:.88em;line-height:1.5"><span class="pill" style="font-size:10px;padding:1px 6px;vertical-align:middle;margin-right:5px">${meth}${quality!=null?` <span class="score" style="font-size:10px">q=${esc(String(quality))}</span>`:''}</span><b style="word-break:break-all">${text}</b>${src?` <span class="sub" style="word-break:break-all">← ${src}</span>`:''}</div>`;
}
function _renderJsonArtifact(data){
  if(Array.isArray(data)){
    const good=data.filter(e=>e&&typeof e==='object'&&_isPrintable(e.text||e.output||''));
    if(!good.length) return '<p class="sub" style="margin:6px 0">No printable decoded results.</p>';
    return good.map(e=>_decodeCard(esc(e.text||e.output||''),esc(e.method||e.type||''),esc(e.token||e.input||e.source||''),null)).join('');
  }
  if(data&&typeof data==='object'){
    let html='';
    if(data.interesting_strings?.length) html+=`<div class="sub" style="margin:8px 0 4px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px">Interesting strings</div><pre style="margin:0 0 10px">${esc(data.interesting_strings.join('\n'))}</pre>`;
    if(data.decoded_constants?.length){
      const good=data.decoded_constants.filter(e=>_isPrintable(e.text||''));
      if(good.length){
        html+=`<div class="sub" style="margin:8px 0 4px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px">Decoded constants</div>`;
        html+=good.map(e=>_decodeCard(esc(e.text||''),esc(e.method||''),esc(e.source||''),e.quality??null)).join('');
      }
    }
    if(data.note) html+=`<p class="sub" style="margin-top:8px">${esc(data.note)}</p>`;
    if(!html) html=`<pre>${esc(JSON.stringify(data,null,2).slice(0,8000))}</pre>`;
    return html;
  }
  return `<pre>${esc(String(data).slice(0,8000))}</pre>`;
}
async function fetchArtifactHtml(url){
  if(artifactCache.has(url)) return artifactCache.get(url);
  try{
    const r=await fetch(url); const t=await r.text();
    let html;
    if(/\.json(\?|$)/i.test(url)){
      try{ html=_renderJsonArtifact(JSON.parse(t)); }
      catch(e){ html=`<pre>${esc(t.slice(0,14000))}${t.length>14000?'\n… (truncated)':''}</pre>`; }
    } else {
      html=`<pre>${esc(t.slice(0,14000))}${t.length>14000?'\n… (truncated)':''}</pre>`;
    }
    artifactCache.set(url,html); return html;
  }catch(e){ return `<span class="bad">${esc(String(e))}</span>`; }
}
function autoLoadArtifacts(){
  const els=Array.from(document.querySelectorAll('.artv-text[data-src]')).filter(el=>el.dataset.loaded!=='1');
  els.slice(0,10).forEach(el=>{
    el.dataset.loaded='1';
    const cached=artifactCache.get(el.dataset.src);
    if(cached){el.innerHTML=cached;return;}
    fetchArtifactHtml(el.dataset.src).then(html=>{el.innerHTML=html;});
  });
}
function imgError(el){ const dl=el.dataset.dl||''; el.outerHTML=`<a class="btn" href="${dl}" target="_blank" style="display:inline-block;margin-top:6px">Download image</a>`; }
function visualsHtml(items){
  const imgs = items.filter(a => a.path && _IMG_EXTS.has(_ext(a.path)));
  if(!imgs.length) return '<p class="warn">No visual artifacts yet. PNG/JPG/etc. artifacts will appear here as they are generated.</p>';
  const sorted = [...imgs].sort((a,b)=>(b.score||0)-(a.score||0));
  return `<div class="row between" style="margin-bottom:10px"><span class="sub">${sorted.length} visual${sorted.length!==1?'s':''} — click image to open full size</span></div><div class="vis-grid">${sorted.map(a=>{
    const rawUrl='/api/raw?path='+enc(a.path);
    const name=esc(a.name||a.path.split(/[/\\]/).pop()||'visual');
    const kind=esc(a.kind||'');
    const p=esc(a.path||'');
    return `<div class="vis-card"><a class="vis-card-img-wrap" href="${rawUrl}" target="_blank"><img src="${rawUrl}" alt="${name}" loading="lazy" onerror="this.style.opacity='.3'"></a><div class="vis-info"><div class="vis-label" title="${name}">${name}</div><div class="vis-footer"><span class="vis-badge">score ${esc(a.score||0)}</span>${kind?`<span class="vis-kind">${kind}</span>`:''} ${a.path?`<button class="vis-btn" onclick="revealInFolder('${p}')">show in folder</button>`:''}</div></div></div>`;
  }).join('')}</div>`;
}
async function revealInFolder(path){
  try{
    const r=await fetch('/api/reveal?path='+enc(path));
    const j=await r.json();
    if(!j.ok) alert('Could not reveal file: '+(j.error||'unknown'));
  }catch(e){ alert('Could not reveal file: '+String(e)); }
}
function filesHtml(files){ return files.map(f=>`<div class="find"><div class="row between"><div><b>${esc(f.rel||f.name)}</b><div class="sub">${esc(f.kind||'')} · ${esc(f.size||0)} bytes</div></div><div class="row"><button class="btn" onclick="previewFile('${enc(f.path)}')">preview</button>${f.path?`<a class="btn" target="_blank" href="/api/raw?path=${enc(f.path)}">raw</a>`:''}</div></div><div id="preview-${esc(f.path||f.name)}"></div></div>`).join('')||'<p class="warn">No files.</p>'; }
async function previewFile(path){ const j=await fetchJson('/api/raw_info?path='+path); alert(JSON.stringify(j,null,2)); }
function projectSettingsHtml(meta){ const p=meta.solver_settings||S.prefs||{}; return `<h3>Project solver settings</h3>${settingsFormHtml('project',p)}<button class="btn primary" onclick="saveProjectSettings('${esc(meta.id)}')">Save project settings</button><pre>${esc(JSON.stringify(p,null,2))}</pre>`; }
async function saveProjectSettings(pid){
  const st=readSettings('project');
  const j=await fetchJson('/api/projects/'+enc(pid)+'/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(st)});
  if(!j.ok){alert(j.error||'failed');return;}
  const pj=await fetchJson('/api/projects/'+enc(pid)+'/compact');
  S.current=pj;
  renderProjectPanel();
}
function manualToolsHtml(files){ const options=files.map(f=>`<option value="${esc(f.path||'')}">${esc(f.rel||f.name)}</option>`).join(''); return `<label>File &nbsp;<select id="toolFile">${options}</select></label><br><label>Tool &nbsp;<select id="toolName">${fileTools.map(t=>`<option>${esc(t)}</option>`).join('')}</select></label><br><br><button class="btn primary" onclick="runTool()">Run tool</button><div id="toolOut"></div>`; }
async function runTool(){ const path=qs('toolFile').value, tool=qs('toolName').value; const fd=new FormData(); fd.append('path',path); fd.append('toolname',tool); const j=await fetchJson('/api/run_tool',{method:'POST',body:fd}); const out=qs('toolOut'); if(!j){out.innerHTML='<span class="err">No response</span>';return;} const lines=[`<span style="opacity:.5">$ ${esc(j.cmd||tool)}</span>`]; if(j.out&&j.out.trim()) lines.push(`<pre style="margin:6px 0 0">${esc(j.out)}</pre>`); if(j.err&&j.err.trim()) lines.push(`<pre class="err" style="margin:6px 0 0">${esc(j.err)}</pre>`); if(!j.ok) lines.push(`<span class="err">exit ${esc(String(j.code??'?'))}</span>`); if(j.missing&&j.missing.length) lines.push(`<span class="err">missing: ${esc(j.missing.join(', '))}</span>`); if(j.install_hint) lines.push(`<span style="opacity:.6">${esc(j.install_hint)}</span>`); out.innerHTML=`<div style="margin-top:10px">${lines.join('')}</div>`; }

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
