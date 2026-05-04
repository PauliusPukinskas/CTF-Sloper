
let files=[], current=null, currentData=null, poller=null, projectPrompt="";
let activeProjectTab=0, selectedFile=0, activeFileTab=0, fileSearch="", fileKindFilter="all";
let uiBusy=false, manualResults={}, lastRenderAt=0;
function nav(id,b){document.querySelectorAll('main section').forEach(s=>s.classList.add('hidden'));document.getElementById(id).classList.remove('hidden');document.querySelectorAll('aside button').forEach(x=>x.classList.remove('active'));b.classList.add('active')}
function pick(){fileInput.click()} fileInput.onchange=()=>{files=[...files,...fileInput.files];renderFiles()}
drop.ondragover=e=>{e.preventDefault();drop.classList.add('drag')};drop.ondragleave=()=>drop.classList.remove('drag');drop.ondrop=e=>{e.preventDefault();drop.classList.remove('drag');files=[...files,...e.dataTransfer.files];renderFiles()}
function removePendingFile(i){files=files.filter((_,idx)=>idx!==i);renderFiles()}
function clearPendingFiles(){files=[];fileInput.value='';renderFiles()}
function renderFiles(){fileCount.innerHTML=files.length?`<div class=row><button type=button class=btn onclick="clearPendingFiles()">clear all</button><span class=pill>${files.length} selected</span></div>`+files.map((f,i)=>`<span class=pill>${esc(f.name)} · ${f.size} bytes <button type=button class=btn onclick="removePendingFile(${i})">remove</button></span>`).join(""):"No files selected"}
async function createProject(){if(!files.length){alert("Pirma pridėk failus");return} if(!title.value.trim())title.value=files[0].name; const fd=new FormData();files.forEach(f=>fd.append("files",f));fd.append("title",title.value);fd.append("statement",statement.value);fd.append("category",category.value);fd.append("auto_start",autoStart.checked?"true":"false");const r=await fetch('/api/projects',{method:'POST',body:fd});const j=await r.json();activeProjectTab=0;selectedFile=0;activeFileTab=0;nav('projects',document.querySelectorAll('aside button')[1]);await loadProjects();await openProject(j.id);startPolling(j.id)}
async function loadProjects(){const r=await fetch('/api/projects');const j=await r.json();projectList.innerHTML=(j.projects||[]).map(p=>{const s=p.summary||{},flags=s.flags||[],ev=s.evidence_board||[],chains=s.top_chains||[],miss=s.missing_tools||[];return `<div class=project><div class=row><b>${esc(p.title)}</b><span class=pill>${esc(p.category)}</span><span class=pill>${esc(p.runtime_status||"")}</span><span class=pill>${p.progress||0}%</span><span class=pill>${flags.length} promoted flags</span><span class=pill>${ev.length} evidence</span><span class=pill>${chains.length} chains</span><span class="${miss.length?'pill bad':'pill ok'}">${miss.length} missing</span></div><div class=progress><div class=bar style="width:${p.progress||0}%"></div></div><div class=sub>${esc(p.stage||"")}</div><button type=button class=btn onclick="openProject('${p.id}')">Open workspace</button><button type=button class=btn onclick="startProject('${p.id}')">Run again</button></div>`}).join("")}
async function startProject(id){await fetch(`/api/projects/${id}/start`,{method:'POST'});startPolling(id);await openProject(id,false)}
function startPolling(id){if(poller)clearInterval(poller);poller=setInterval(async()=>{await loadProjects();if(current===id&&!uiBusy&&activeProjectTab<2)await openProject(id,false,true)},5000)}
async function openProject(id,scroll=true,isPoll=false){current=id;const oldTab=activeProjectTab,oldFile=selectedFile,oldFileTab=activeFileTab;const r=await fetch(`/api/projects/${id}`);const newData=await r.json();currentData=newData;activeProjectTab=oldTab;selectedFile=oldFile;activeFileTab=oldFileTab;if(isPoll&&uiBusy)return;if(isPoll&&activeProjectTab>=7)return;renderProject();if(scroll&&!isPoll)projectView.scrollIntoView({behavior:'smooth'})}
function renderProject(){const j=currentData,rep=j.report||{},meta=j.project||{},job=j.job||{},files=rep.files||[],sum=rep.summary||{};if(selectedFile>=files.length)selectedFile=0;projectPrompt=rep.ai_prompt||"";const kinds=sum.kinds||{};projectView.innerHTML=`<div class=card><h2>${esc(meta.title||"Project")}</h2><div class=grid3><div class=metric><b>${job.progress||0}%</b><div class=sub>progress</div></div><div class=metric><b>${files.length}</b><div class=sub>files</div></div><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>promoted flags</div></div><div class=metric><b>${(sum.verified_flags||[]).length}</b><div class=sub>verified candidates</div></div><div class=metric><b>${(sum.evidence_board||[]).length}</b><div class=sub>evidence</div></div><div class=metric><b>${(sum.top_chains||[]).length}</b><div class=sub>chains</div></div><div class=metric><b>${(sum.agents||[]).length}</b><div class=sub>agents</div></div><div class=metric><b>${(sum.transformations||[]).length}</b><div class=sub>transforms</div></div><div class=metric><b>${(sum.verifyloops||[]).reduce((a,x)=>a+((x.tools||[]).length),0)}</b><div class=sub>auto tools</div></div></div><div class=progress><div class=bar style="width:${job.progress||0}%"></div></div><div class=row><span class=pill>ID ${esc(meta.id||"")}</span><span class=pill>${esc(meta.category||"")}</span><span class=pill>${esc(job.stage||"")}</span>${Object.entries(kinds).map(([k,v])=>`<span class=pill>${esc(k)}:${v}</span>`).join("")}</div></div><div class=card><div class=tabs>${["Overview","Batch Lab","ZIP Scan","SLOPER Bench","AutoPilot Review","Health","Answer Candidates","Flag Wrappers","Unresolved","Verified Flags","Artifacts","Visual Lab","Recipes","Review","Artifact Graph","Agents","Transforms","Hypotheses","Evidence Board","Workflow","Files","Notes","Logs"].map((t,i)=>`<button type=button class="${i===activeProjectTab?'on':''}" onclick="setProjectTab(${i})">${t}</button>`).join("")}</div><div id=proj0 class="${activeProjectTab===0?'':'hidden'}">${multiStepForgeDashboard(meta,sum)}</div><div id=proj1 class="${activeProjectTab===1?'':'hidden'}">${solveTraceHtml(sum.solve_trace||[])}</div><div id=proj2 class="${activeProjectTab===2?'':'hidden'}">${alternateFlagsHtml(sum.alternate_flag_candidates||[])}</div><div id=proj3 class="${activeProjectTab===3?'':'hidden'}">${autoPilotReviewHtml(sum.autopilot_reviews||[])}</div><div id=proj4 class="${activeProjectTab===4?'':'hidden'}">${evidenceScoresHtml(sum.evidence_scored_candidates||[])}</div><div id=proj5 class="${activeProjectTab===5?'':'hidden'}">${answerCandidatesHtml(sum.answer_candidates||[])}</div><div id=proj6 class="${activeProjectTab===6?'':'hidden'}">${flagWrappersHtml(sum.flag_wrapping_helpers||[])}</div><div id=proj7 class="${activeProjectTab===7?'':'hidden'}">${weakFlagsHtml(sum.weak_flag_candidates||[])}</div><div id=proj8 class="${activeProjectTab===8?'':'hidden'}">${artifactsHtml(sum.artifacts||[])}</div><div id=proj9 class="${activeProjectTab===9?'':'hidden'}">${visualLabHtml(sum.artifacts||[])}</div><div id=proj10 class="${activeProjectTab===10?'':'hidden'}">${agentTraceHtml(sum.agent_trace||[])}</div><div id=proj11 class="${activeProjectTab===11?'':'hidden'}">${verifiedFlagsHtml(sum.verified_flags||[])}</div><div id=proj12 class="${activeProjectTab===12?'':'hidden'}">${unresolvedHtml(sum.unresolved_plan||[])}</div><div id=proj13 class="${activeProjectTab===13?'':'hidden'}">${recipesHtml(sum.recipes||[])}</div><div id=proj14 class="${activeProjectTab===14?'':'hidden'}">${filesWorkspace(files)}</div><div id=proj15 class="${activeProjectTab===15?'':'hidden'}">${projectChat(meta.id)}</div><div id=proj16 class="${activeProjectTab===16?'':'hidden'}"><pre>${esc(j.log||"")}</pre></div></div>`}
function setProjectTab(i){activeProjectTab=i;renderProject()}
function projectOverview(meta,sum){return `<h3>Statement</h3><pre>${esc(meta.statement||"")}</pre><h3>Promoted verified flag candidates</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> from ${esc(x.file)}</span></div>`).join("")||'<p class=warn>No promoted verified flag yet.</p>'}<h3>Top chained results</h3>${(sum.top_chains||[]).slice(0,14).map(x=>`<div class=find><span class=score>${x.score||0}</span> <b>${esc(x.type||"chain")}</b> <span class=pill>${esc(x.file||"")}</span><pre>${esc(x.output||"")}</pre></div>`).join("")||'<p class=warn>No chain results yet.</p>'}<h3>Missing tools from auto-run</h3>${(sum.missing_tools||[]).map(x=>`<span class="pill bad">${esc(x)}</span>`).join("")||'<span class="pill ok">No missing tool messages from analyzed outputs.</span>'}<div class=row><button type=button class=btn onclick="copyProjectPrompt()">Copy project context</button><button type=button class=btn onclick="alert('Project context copied for local notes. Assistant panel is disabled in FINAL.')">Notes only</button></div>`}








function challengeLabProjectHtml(sum){
 const arts=(sum.artifacts||[]).filter(a=>String(a.kind||"").includes("deeppattern")||String(a.source||"").includes("SLOPER"));
 const rec=(sum.recipes||[]).filter(r=>["crypto_encoding_stack","image_lsb_visual","binary_string_decrypt","crypto_rsa_params","jwt_decode"].includes(String(r.name||"")));
 return `<h3>SLOPER overview</h3><div class=grid3><div class=metric><b>${arts.length}</b><div class=sub>deep artifacts</div></div><div class=metric><b>${rec.length}</b><div class=sub>deep recipes</div></div><div class=metric><b>${(sum.verified_flags||[]).length}</b><div class=sub>strict candidates</div></div></div><h3>Deep artifacts</h3>${artifactsHtml(arts)}<h3>Deep recipes</h3>${recipesHtml(rec)}`
}
function fileSLOPERHtml(f){
 const arts=(f.artifacts||[]).filter(a=>String(a.kind||"").includes("deeppattern")||String(a.source||"").includes("SLOPER")||String(a.kind||"").includes("lsb_variant"));
 const deepChains=(f.chain_results||[]).filter(c=>String(c.type||"").includes("deeppattern")).slice(0,60);
 return `<h3>SLOPER file report</h3><div class=grid3><div class=metric><b>${arts.length}</b><div class=sub>deep artifacts</div></div><div class=metric><b>${deepChains.length}</b><div class=sub>deep chains</div></div><div class=metric><b>${(f.verified_flags_visible||[]).length}</b><div class=sub>strict flags</div></div></div><h3>Deep artifacts</h3>${artifactsHtml(arts)}<h3>Deep chains</h3>${deepChains.map(c=>`<details class=cardish open><summary><b>${esc(c.type||"chain")}</b> <span class=pill>score ${c.score||0}</span></summary>${(c.flags||[]).map(x=>`<div class=flag>${esc(x)}</div>`).join("")}<pre>${esc(c.output||"")}</pre></details>`).join("")||'<p class=warn>No SLOPER chain results.</p>'}<h3>Deep recipes</h3>${recipesHtml((f.recipe_runs||[]).map(x=>({...x,file:f.rel,kind:f.kind})).filter(r=>r.score>=84))}`
}

function recipesHtml(items){
 if(!items||!items.length)return '<p class=warn>No recipes yet.</p>';
 return items.slice(0,180).map(r=>`<div class=find><div class=row><span class=score>${r.score||0}</span><b> ${esc(r.name||"recipe")}</b><span class=pill>${esc(r.file||"")}</span><span class=pill>${esc(r.kind||"")}</span></div><p>${esc(r.why||"")}</p><h4>Actions</h4>${(r.actions||[]).map(a=>`<span class=pill>${esc(a)}</span>`).join("")}<h4>Recipe artifacts</h4>${artifactsHtml(r.artifacts||[])}</div>`).join("")
}
function artifactGraphHtml(items){
 if(!items||!items.length)return '<p class=warn>No artifact graph yet.</p>';
 return items.map(g=>{const graph=g.graph||{};const nodes=graph.nodes||[],edges=graph.edges||[];return `<div class=find><h3>Graph: ${esc(g.file||"project")}</h3><div class=row><span class=pill>${nodes.length} nodes</span><span class=pill>${edges.length} edges</span></div>${nodes.slice(0,80).map(n=>`<div class=find><b>${artifactIcon(n.kind)} ${esc(n.label||n.id)}</b> <span class=pill>${esc(n.kind||"")}</span> <span class=score>${n.score||0}</span><br><span class=sub>${esc(n.path||"")}</span></div>`).join("")}</div>`}).join("")
}
function fileSLOPERHtml(f){
 const h=f.candidate_health||{};
 return `<h3>SLOPER health</h3><div class=grid3><div class=metric><b>${h.promoted_flags||0}</b><div class=sub>promoted</div></div><div class=metric><b>${h.visible_verified_candidates||0}</b><div class=sub>visible verified</div></div><div class=metric><b>${h.negative_or_noisy_candidates||0}</b><div class=sub>hidden noisy</div></div><div class=metric><b>${h.noise_ratio||0}</b><div class=sub>noise ratio</div></div></div><h3>Top recipes</h3>${recipesHtml((f.recipe_runs||[]).map(x=>({...x,file:f.rel,kind:f.kind})))}<h3>Solver brief</h3>${artifactsHtml((f.artifacts||[]).filter(a=>String(a.kind||"").includes("solver_brief")))}`
}
async function runSmartRecipe(path){
 uiBusy=true;manualResults[path]='<div class=find>Running SLOPER recipe engine...</div>';renderProject();
 const fd=new FormData();fd.append('path',path);
 try{const r=await fetch('/api/run_recipe',{method:'POST',body:fd});const j=await r.json();manualResults[path]=j.ok?(`<h3>SLOPER manual result · ${esc(j.kind||"")}</h3><h4>Flags</h4>${(j.flags||[]).map(x=>`<div class=flag>${esc(x)}</div>`).join("")||'<p class=warn>No promoted flag.</p>'}<h4>Recipes</h4>${recipesHtml(j.recipes||[])}<h4>Artifacts</h4>${artifactsHtml(j.artifacts||[])}<h4>Findings</h4>${evidenceBoardHtml(j.findings||[])}`):`<pre>${esc(j.error||JSON.stringify(j,null,2))}</pre>`}catch(e){manualResults[path]=`<pre>${esc(String(e))}</pre>`}
 uiBusy=false;renderProject();
}







function cyberSprintBenchHtml(){
 return `<h3>ZIP Scan</h3><p class=sub>Runs a fast static benchmark over the local Cyber Sprint ZIP. It does not execute challenge binaries or use web.</p><input id=csBenchPath class=search value="/mnt/data/Cyber Sprint 2026 1 etapas.zip"><button type=button class="btn primary" onclick="runCyberSprintBench()">Run ZIP Scan</button><div id=csBenchOut></div>`
}
async function runCyberSprintBench(){
 const box=document.getElementById('csBenchOut'); if(box)box.innerHTML='<div class=find>Benchmarking real ZIP...</div>';
 const p=document.getElementById('csBenchPath').value;
 try{
  const r=await fetch('/api/cybersprint_benchmark?path='+encodeURIComponent(p));
  const j=await r.json();
  if(box)box.innerHTML=cyberSprintBenchResultHtml(j);
 }catch(e){ if(box)box.innerHTML='<pre>'+esc(String(e))+'</pre>'}
}
function cyberSprintBenchResultHtml(j){
 if(!j.ok)return `<div class=find><b class=bad>Failed</b><pre>${esc(JSON.stringify(j,null,2))}</pre></div>`;
 return `<div class=find><h3>ZIP Scan</h3><div class=grid3><div class=metric><b>${j.total||0}</b><div class=sub>challenges</div></div><div class=metric><b>${j.with_flags||0}</b><div class=sub>strict flags</div></div><div class=metric><b>${j.with_signal||0}</b><div class=sub>with signal</div></div><div class=metric><b>${j.unresolved||0}</b><div class=sub>unresolved</div></div></div>${(j.results||[]).map(x=>`<div class=find><div class=row><b>${esc(x.title||"")}</b><span class=pill>${esc(x.status||"")}</span><span class=pill>${x.files||0} files</span></div>${(x.flags||[]).map(f=>`<div class=flag>${esc(f)}</div>`).join("")}${(x.answers||[]).slice(0,5).map(a=>`<span class=pill>${esc(a)}</span>`).join("")}<details><summary>artifacts / notes</summary><pre>${esc(JSON.stringify({artifacts:x.artifacts,notes:x.notes},null,2))}</pre></details></div>`).join("")}</div>`
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>evidence-backed flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${(sum.flag_wrapping_helpers||[]).length}</b><div class=sub>wrapper hints</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>Runs multi-step agents based on real writeups: numeric table static extraction, Piet grid extraction, LSB streams, tile puzzle aids, recursive child artifacts and strict evidence scoring.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,18))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function solveTraceHtml(items){
 if(!items||!items.length)return '<p class=warn>No solve trace yet. Run SLOPER Agents or analyze files.</p>';
 return items.slice(0,700).map(x=>`<div class=find><div class=row><span class=score>${x.confidence||x.score||0}</span><b>${esc(x.stage||x.step||"")}</b><span class=pill>${esc(x.file||"")}</span>${x.flag?`<span class=flag>${esc(x.flag)}</span>`:""}</div><p>${esc(x.detail||"")}</p>${x.artifact?`<button type=button class=btn onclick="copyText('${escAttr(x.artifact)}')">copy artifact path</button> <a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.artifact)}">open</a>`:""}</div>`).join("")
}
function weakFlagsHtml(items){
 if(!items||!items.length)return '<p class=ok>No weak flags. Good: promoted flags require solve evidence.</p>';
 return items.slice(0,160).map(x=>`<div class=find><div class=row><span class=score>${x.support||0}</span><b class=warn>${esc(x.flag||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.flag||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span></div><p class=sub>Not promoted because solve evidence is too weak.</p><p>${(x.sources||[]).map(s=>`<span class=pill>${esc(s)}</span>`).join("")}</p></div>`).join("")
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(sum){
 return `<h3>SLOPER Review</h3>${healthHtml(sum.health||{})}<h3>AutoPilot Review</h3>${autoPilotReviewHtml(sum.autopilot_reviews||[])}<h3>Answer Candidates</h3>${answerCandidatesHtml(sum.answer_candidates||[])}<h3>Flag Wrappers</h3>${flagWrappersHtml(sum.flag_wrapping_helpers||[])}<h3>CyberSprint artifacts</h3>${artifactsHtml((sum.artifacts||[]).filter(a=>String(a.source||"").includes("SLOPER")||String(a.source||"").includes("FlowForge")||String(a.source||"").includes("RealBench")||String(a.kind||"").includes("time_anomaly")||String(a.kind||"").includes("pcap")||String(a.kind||"").includes("pyc")||String(a.kind||"").includes("artifact_log")).slice(0,300))}`
}
function fileSLOPERHtml(f){
 const rb=(f.artifacts||[]).filter(a=>String(a.source||"").includes("SLOPER")||String(a.source||"").includes("FlowForge")||String(a.source||"").includes("RealBench")||String(a.kind||"").includes("visual")||String(a.kind||"").includes("pcap")||String(a.kind||"").includes("pyc")||String(a.kind||"").includes("decompressed")||String(a.kind||"").includes("artifact_log")||String(a.kind||"").includes("time_anomaly"));
 return `<h3>SLOPER file report</h3><div class=grid3><div class=metric><b>${(f.flags||[]).length}</b><div class=sub>ctf_cs flags</div></div><div class=metric><b>${(f.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${rb.length}</b><div class=sub>CS artifacts</div></div></div><h3>AutoPilot</h3>${autoPilotReviewHtml([{file:f.rel,...(f.autopilot_review||{})}])}<h3>Answer Candidates</h3>${answerCandidatesHtml(f.answer_candidates||[])}<h3>Flag Wrappers</h3>${flagWrappersHtml(f.flag_wrapping_helpers||[])}<h3>CyberSprint artifacts</h3>${artifactsHtml(rb)}<h3>Visual Lab</h3>${visualLabHtml(rb)}`
}

function flowBenchHtml(){
 return `<h3>SLOPER generated benchmark</h3><p class=sub>Runs a generated benchmark across encoding, XOR, compression, JWT, classical ciphers, and non-format answers.</p><button type=button class="btn primary" onclick="runMegaBenchmark()">Run SLOPER Benchmark</button><div id=megaOut></div><h3>Normal challenge intake</h3><div class=find><b>Use title + statement + files.</b><p>Best review order: AutoPilot Review → Summary → Answer Candidates → Flag Wrappers → Verified Flags → Artifacts → Recipes → Visual Lab.</p></div>`
}



function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>evidence-backed flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${(sum.flag_wrapping_helpers||[]).length}</b><div class=sub>wrapper hints</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>Runs multi-step agents based on real writeups: numeric table static extraction, Piet grid extraction, LSB streams, tile puzzle aids, recursive child artifacts and strict evidence scoring.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,18))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function solveTraceHtml(items){
 if(!items||!items.length)return '<p class=warn>No solve trace yet. Run SLOPER Agents or analyze files.</p>';
 return items.slice(0,700).map(x=>`<div class=find><div class=row><span class=score>${x.confidence||x.score||0}</span><b>${esc(x.stage||x.step||"")}</b><span class=pill>${esc(x.file||"")}</span>${x.flag?`<span class=flag>${esc(x.flag)}</span>`:""}</div><p>${esc(x.detail||"")}</p>${x.artifact?`<button type=button class=btn onclick="copyText('${escAttr(x.artifact)}')">copy artifact path</button> <a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.artifact)}">open</a>`:""}</div>`).join("")
}
function weakFlagsHtml(items){
 if(!items||!items.length)return '<p class=ok>No weak flags. Good: promoted flags require solve evidence.</p>';
 return items.slice(0,160).map(x=>`<div class=find><div class=row><span class=score>${x.support||0}</span><b class=warn>${esc(x.flag||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.flag||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span></div><p class=sub>Not promoted because solve evidence is too weak.</p><p>${(x.sources||[]).map(s=>`<span class=pill>${esc(s)}</span>`).join("")}</p></div>`).join("")
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>strict flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.evidence_scored_candidates||[]).length}</b><div class=sub>evidence-scored</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${(sum.agent_trace||[]).length}</b><div class=sub>agent steps</div></div><div class=metric><b>${(sum.flag_wrapping_helpers||[]).length}</b><div class=sub>wrapper hints</div></div></div><div class=find><h3>Aggressive AutoSolve</h3><p class=sub>Runs multi-pass local agents again: crypto, forensics, stego, rev, pcap, text/OSINT, child artifacts and evidence scoring.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run Aggressive Agents</button></div><h3>AutoPilot</h3>${autoPilotReviewHtml(sum.autopilot_reviews||[])}<h3>Best Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
async function runAggressiveAgents(pid){
 const fd=new FormData(); fd.append('pid',pid);
 const r=await fetch('/api/run_aggressive_agents',{method:'POST',body:fd}); const j=await r.json();
 alert(j.ok?'Aggressive agents scheduled. Refresh in a moment.':JSON.stringify(j));
}
function evidenceScoresHtml(items){
 if(!items||!items.length)return '<p class=warn>No evidence-scored candidates yet.</p>';
 return items.slice(0,160).map(x=>`<div class=find><div class=row><span class=score>${x.evidence_score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span></div><p class=sub>${(x.sources||[]).map(s=>`<span class=pill>${esc(s)}</span>`).join("")}</p></div>`).join("")
}
function agentTraceHtml(items){
 if(!items||!items.length)return '<p class=warn>No agent trace yet.</p>';
 return items.slice(0,500).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.step||"")}</b><span class=pill>${esc(x.file||"")}</span></div><p>${esc(x.detail||"")}</p>${x.artifact?`<button type=button class=btn onclick="copyText('${escAttr(x.artifact)}')">copy artifact path</button> <a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.artifact)}">open</a>`:""}</div>`).join("")
}

function autoPilotReviewHtml(items){
 if(!items||!items.length)return '<p class=warn>No AutoPilot reviews yet.</p>';
 return items.map(x=>`<div class=find><div class=row><b>${esc(x.file||"")}</b><span class=pill>${esc(x.status||"")}</span>${(x.statement_keywords||[]).map(k=>`<span class=pill>${esc(k)}</span>`).join("")}</div>${x.top_flag?`<div class=flag>${esc(x.top_flag)}</div>`:""}${x.top_answer?`<p><b>Top answer:</b> ${esc(x.top_answer)}</p>`:""}${x.top_artifact&&x.top_artifact.path?`<p><b>Top artifact:</b> ${esc(x.top_artifact.name||"")} <button type=button class=btn onclick="copyText('${escAttr(x.top_artifact.path)}')">copy path</button> <a class=btn target=_blank href="${x.top_artifact.url||('/api/raw?path='+encodeURIComponent(x.top_artifact.path))}">open</a></p>`:""}<h4>Actions</h4>${(x.actions||[]).map(a=>`<span class=pill>${esc(a)}</span>`).join("")}</div>`).join("")
}
function flagWrappersHtml(items){
 if(!items||!items.length)return '<p class=warn>No wrapper suggestions. This is normal if strict ctf_cs flag already exists.</p>';
 return items.slice(0,100).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.suggested_flag||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.suggested_flag||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span></div><p><b>From answer:</b> ${esc(x.answer||"")}</p><p class=sub>${esc(x.why||"")}</p></div>`).join("")
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>evidence-backed flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${(sum.flag_wrapping_helpers||[]).length}</b><div class=sub>wrapper hints</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>Runs multi-step agents based on real writeups: numeric table static extraction, Piet grid extraction, LSB streams, tile puzzle aids, recursive child artifacts and strict evidence scoring.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,18))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function solveTraceHtml(items){
 if(!items||!items.length)return '<p class=warn>No solve trace yet. Run SLOPER Agents or analyze files.</p>';
 return items.slice(0,700).map(x=>`<div class=find><div class=row><span class=score>${x.confidence||x.score||0}</span><b>${esc(x.stage||x.step||"")}</b><span class=pill>${esc(x.file||"")}</span>${x.flag?`<span class=flag>${esc(x.flag)}</span>`:""}</div><p>${esc(x.detail||"")}</p>${x.artifact?`<button type=button class=btn onclick="copyText('${escAttr(x.artifact)}')">copy artifact path</button> <a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.artifact)}">open</a>`:""}</div>`).join("")
}
function weakFlagsHtml(items){
 if(!items||!items.length)return '<p class=ok>No weak flags. Good: promoted flags require solve evidence.</p>';
 return items.slice(0,160).map(x=>`<div class=find><div class=row><span class=score>${x.support||0}</span><b class=warn>${esc(x.flag||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.flag||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span></div><p class=sub>Not promoted because solve evidence is too weak.</p><p>${(x.sources||[]).map(s=>`<span class=pill>${esc(s)}</span>`).join("")}</p></div>`).join("")
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(sum){
 return `<h3>SLOPER Review</h3>${healthHtml(sum.health||{})}<h3>AutoPilot Review</h3>${autoPilotReviewHtml(sum.autopilot_reviews||[])}<h3>Top Answer Candidates</h3>${answerCandidatesHtml(sum.answer_candidates||[])}<h3>Flag Wrappers</h3>${flagWrappersHtml(sum.flag_wrapping_helpers||[])}<h3>High-value artifacts</h3>${artifactsHtml((sum.artifacts||[]).filter(a=>String(a.source||"").includes("SLOPER")||String(a.source||"").includes("MegaBench")||String(a.source||"").includes("RealBench")||String(a.source||"").includes("VisualForge")||String(a.kind||"").includes("chain")||String(a.kind||"").includes("decompressed")||String(a.kind||"").includes("pyc")||String(a.kind||"").includes("pcap")).slice(0,260))}`
}
function fileSLOPERHtml(f){
 const rb=(f.artifacts||[]).filter(a=>String(a.source||"").includes("SLOPER")||String(a.source||"").includes("MegaBench")||String(a.source||"").includes("RealBench")||String(a.source||"").includes("VisualForge")||String(a.kind||"").includes("visual")||String(a.kind||"").includes("pcap")||String(a.kind||"").includes("pyc")||String(a.kind||"").includes("decompressed")||String(a.kind||"").includes("chain"));
 return `<h3>SLOPER file report</h3><div class=grid3><div class=metric><b>${(f.flags||[]).length}</b><div class=sub>ctf_cs flags</div></div><div class=metric><b>${(f.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(f.flag_wrapping_helpers||[]).length}</b><div class=sub>wrapper helpers</div></div><div class=metric><b>${rb.length}</b><div class=sub>artifacts</div></div></div><h3>AutoPilot</h3>${autoPilotReviewHtml([{file:f.rel,...(f.autopilot_review||{})}])}<h3>Answer Candidates</h3>${answerCandidatesHtml(f.answer_candidates||[])}<h3>Flag Wrappers</h3>${flagWrappersHtml(f.flag_wrapping_helpers||[])}<h3>High-value artifacts</h3>${artifactsHtml(rb)}<h3>Visual Lab</h3>${visualLabHtml(rb)}`
}


function cyberSprintBenchHtml(){
 return `<h3>ZIP Scan</h3><p class=sub>Runs a fast static benchmark over the local Cyber Sprint ZIP. It does not execute challenge binaries or use web.</p><input id=csBenchPath class=search value="/mnt/data/Cyber Sprint 2026 1 etapas.zip"><button type=button class="btn primary" onclick="runCyberSprintBench()">Run ZIP Scan</button><div id=csBenchOut></div>`
}
async function runCyberSprintBench(){
 const box=document.getElementById('csBenchOut'); if(box)box.innerHTML='<div class=find>Benchmarking real ZIP...</div>';
 const p=document.getElementById('csBenchPath').value;
 try{
  const r=await fetch('/api/cybersprint_benchmark?path='+encodeURIComponent(p));
  const j=await r.json();
  if(box)box.innerHTML=cyberSprintBenchResultHtml(j);
 }catch(e){ if(box)box.innerHTML='<pre>'+esc(String(e))+'</pre>'}
}
function cyberSprintBenchResultHtml(j){
 if(!j.ok)return `<div class=find><b class=bad>Failed</b><pre>${esc(JSON.stringify(j,null,2))}</pre></div>`;
 return `<div class=find><h3>ZIP Scan</h3><div class=grid3><div class=metric><b>${j.total||0}</b><div class=sub>challenges</div></div><div class=metric><b>${j.with_flags||0}</b><div class=sub>strict flags</div></div><div class=metric><b>${j.with_signal||0}</b><div class=sub>with signal</div></div><div class=metric><b>${j.unresolved||0}</b><div class=sub>unresolved</div></div></div>${(j.results||[]).map(x=>`<div class=find><div class=row><b>${esc(x.title||"")}</b><span class=pill>${esc(x.status||"")}</span><span class=pill>${x.files||0} files</span></div>${(x.flags||[]).map(f=>`<div class=flag>${esc(f)}</div>`).join("")}${(x.answers||[]).slice(0,5).map(a=>`<span class=pill>${esc(a)}</span>`).join("")}<details><summary>artifacts / notes</summary><pre>${esc(JSON.stringify({artifacts:x.artifacts,notes:x.notes},null,2))}</pre></details></div>`).join("")}</div>`
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>evidence-backed flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${(sum.flag_wrapping_helpers||[]).length}</b><div class=sub>wrapper hints</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>Runs multi-step agents based on real writeups: numeric table static extraction, Piet grid extraction, LSB streams, tile puzzle aids, recursive child artifacts and strict evidence scoring.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,18))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function solveTraceHtml(items){
 if(!items||!items.length)return '<p class=warn>No solve trace yet. Run SLOPER Agents or analyze files.</p>';
 return items.slice(0,700).map(x=>`<div class=find><div class=row><span class=score>${x.confidence||x.score||0}</span><b>${esc(x.stage||x.step||"")}</b><span class=pill>${esc(x.file||"")}</span>${x.flag?`<span class=flag>${esc(x.flag)}</span>`:""}</div><p>${esc(x.detail||"")}</p>${x.artifact?`<button type=button class=btn onclick="copyText('${escAttr(x.artifact)}')">copy artifact path</button> <a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.artifact)}">open</a>`:""}</div>`).join("")
}
function weakFlagsHtml(items){
 if(!items||!items.length)return '<p class=ok>No weak flags. Good: promoted flags require solve evidence.</p>';
 return items.slice(0,160).map(x=>`<div class=find><div class=row><span class=score>${x.support||0}</span><b class=warn>${esc(x.flag||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.flag||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span></div><p class=sub>Not promoted because solve evidence is too weak.</p><p>${(x.sources||[]).map(s=>`<span class=pill>${esc(s)}</span>`).join("")}</p></div>`).join("")
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(sum){
 return `<h3>SLOPER Review</h3>${healthHtml(sum.health||{})}<h3>AutoPilot Review</h3>${autoPilotReviewHtml(sum.autopilot_reviews||[])}<h3>Answer Candidates</h3>${answerCandidatesHtml(sum.answer_candidates||[])}<h3>Flag Wrappers</h3>${flagWrappersHtml(sum.flag_wrapping_helpers||[])}<h3>CyberSprint artifacts</h3>${artifactsHtml((sum.artifacts||[]).filter(a=>String(a.source||"").includes("SLOPER")||String(a.source||"").includes("FlowForge")||String(a.source||"").includes("RealBench")||String(a.kind||"").includes("time_anomaly")||String(a.kind||"").includes("pcap")||String(a.kind||"").includes("pyc")||String(a.kind||"").includes("artifact_log")).slice(0,300))}`
}
function fileSLOPERHtml(f){
 const rb=(f.artifacts||[]).filter(a=>String(a.source||"").includes("SLOPER")||String(a.source||"").includes("FlowForge")||String(a.source||"").includes("RealBench")||String(a.kind||"").includes("visual")||String(a.kind||"").includes("pcap")||String(a.kind||"").includes("pyc")||String(a.kind||"").includes("decompressed")||String(a.kind||"").includes("artifact_log")||String(a.kind||"").includes("time_anomaly"));
 return `<h3>SLOPER file report</h3><div class=grid3><div class=metric><b>${(f.flags||[]).length}</b><div class=sub>ctf_cs flags</div></div><div class=metric><b>${(f.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${rb.length}</b><div class=sub>CS artifacts</div></div></div><h3>AutoPilot</h3>${autoPilotReviewHtml([{file:f.rel,...(f.autopilot_review||{})}])}<h3>Answer Candidates</h3>${answerCandidatesHtml(f.answer_candidates||[])}<h3>Flag Wrappers</h3>${flagWrappersHtml(f.flag_wrapping_helpers||[])}<h3>CyberSprint artifacts</h3>${artifactsHtml(rb)}<h3>Visual Lab</h3>${visualLabHtml(rb)}`
}

function flowBenchHtml(){
 return `<h3>SLOPER 100-case local benchmark</h3><p class=sub>This generates 100 temporary synthetic CTF-style cases across encoding, XOR, compression, JWT, and non-format answers. It does not ship sample challenges and deletes temporary data.</p><button type=button class="btn primary" onclick="runSLOPERmark()">Run 100-case SLOPER</button><div id=megaOut></div><h3>Recommended workflow</h3><div class=find><b>For your normal challenge format:</b><p>Use title + statement + files. Then review in this order: Summary → Answer Candidates → Verified Flags → Artifacts → Recipes → Visual Lab → Files/Tools.</p></div>`
}
async function runSLOPERmark(){
 const box=document.getElementById('megaOut'); if(box)box.innerHTML='<div class=find>Running 100-case benchmark...</div>';
 try{
  const r=await fetch('/api/mega_benchmark',{method:'POST'});
  const j=await r.json();
  if(box)box.innerHTML=megaBenchResultHtml(j);
 }catch(e){ if(box)box.innerHTML=`<pre>${esc(String(e))}</pre>` }
}
function megaBenchResultHtml(j){
 if(!j.ok)return `<div class=find><b class=bad>Benchmark failed or partially failed</b><p>${j.passed||0}/${j.total||0} passed</p><pre>${esc(j.error||'')}</pre>${(j.results||[]).filter(x=>!x.ok).slice(0,30).map(x=>`<div class=find><b class=bad>${esc(x.name)}</b><p>Expected: ${esc(x.expected||'')}</p><pre>${esc(JSON.stringify({flags:x.flags,answers:x.answers},null,2))}</pre></div>`).join('')}</div>`;
 return `<div class=find><h3 class=ok>Passed ${j.passed}/${j.total}</h3><pre>${esc(JSON.stringify(j.by_kind||{},null,2))}</pre>${(j.results||[]).slice(0,20).map(x=>`<span class=pill>${esc(x.name)} </span>`).join('')}</div>`;
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>evidence-backed flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${(sum.flag_wrapping_helpers||[]).length}</b><div class=sub>wrapper hints</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>Runs multi-step agents based on real writeups: numeric table static extraction, Piet grid extraction, LSB streams, tile puzzle aids, recursive child artifacts and strict evidence scoring.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,18))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function solveTraceHtml(items){
 if(!items||!items.length)return '<p class=warn>No solve trace yet. Run SLOPER Agents or analyze files.</p>';
 return items.slice(0,700).map(x=>`<div class=find><div class=row><span class=score>${x.confidence||x.score||0}</span><b>${esc(x.stage||x.step||"")}</b><span class=pill>${esc(x.file||"")}</span>${x.flag?`<span class=flag>${esc(x.flag)}</span>`:""}</div><p>${esc(x.detail||"")}</p>${x.artifact?`<button type=button class=btn onclick="copyText('${escAttr(x.artifact)}')">copy artifact path</button> <a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.artifact)}">open</a>`:""}</div>`).join("")
}
function weakFlagsHtml(items){
 if(!items||!items.length)return '<p class=ok>No weak flags. Good: promoted flags require solve evidence.</p>';
 return items.slice(0,160).map(x=>`<div class=find><div class=row><span class=score>${x.support||0}</span><b class=warn>${esc(x.flag||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.flag||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span></div><p class=sub>Not promoted because solve evidence is too weak.</p><p>${(x.sources||[]).map(s=>`<span class=pill>${esc(s)}</span>`).join("")}</p></div>`).join("")
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(sum){
 return `<h3>SLOPER Review</h3>${healthHtml(sum.health||{})}<h3>Top Answer Candidates</h3>${answerCandidatesHtml(sum.answer_candidates||[])}<h3>Top Artifacts</h3>${artifactsHtml((sum.artifacts||[]).filter(a=>String(a.source||"").includes("SLOPER")||String(a.source||"").includes("RealBench")||String(a.source||"").includes("VisualForge")||String(a.kind||"").includes("chain")||String(a.kind||"").includes("decompressed")||String(a.kind||"").includes("pyc")||String(a.kind||"").includes("pcap")).slice(0,240))}<h3>Unresolved plan</h3>${unresolvedHtml(sum.unresolved_plan||[])}`
}
function fileSLOPERHtml(f){
 const rb=(f.artifacts||[]).filter(a=>String(a.source||"").includes("SLOPER")||String(a.source||"").includes("RealBench")||String(a.source||"").includes("VisualForge")||String(a.kind||"").includes("visual")||String(a.kind||"").includes("pcap")||String(a.kind||"").includes("pyc")||String(a.kind||"").includes("decompressed")||String(a.kind||"").includes("chain"));
 return `<h3>SLOPER file report</h3><div class=grid3><div class=metric><b>${(f.flags||[]).length}</b><div class=sub>ctf_cs flags</div></div><div class=metric><b>${(f.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${rb.length}</b><div class=sub>artifacts</div></div></div><h3>Answer Candidates</h3>${answerCandidatesHtml(f.answer_candidates||[])}<h3>High-value artifacts</h3>${artifactsHtml(rb)}<h3>Visual Lab</h3>${visualLabHtml(rb)}`
}

function batchLabHtml(){
 return `<h3>Batch Lab</h3><p class=sub>Import a full CTF ZIP and split it into one project per challenge folder.</p><div class=find><h4>Upload ZIP and split</h4><input id=batchZip type=file accept=".zip"><label><input id=batchAuto type=checkbox> auto-start analysis</label> <button type=button class="btn primary" onclick="batchImportZip()">Import ZIP</button></div><div class=find><h4>Use local CTF ZIP path</h4><input id=batchPath class=search value="~/Downloads/Cyber Sprint 2026 1 etapas.zip"><label><input id=batchPathAuto type=checkbox> auto-start analysis</label> <button type=button class="btn primary" onclick="batchImportPath()">Import Path</button> <button type=button class=btn onclick="realbenchManifest()">Manifest</button></div><button type=button class=btn onclick="batchSummary()">Refresh Batch Summary</button><div id=batchOut></div>`
}
async function batchImportZip(){
 const f=document.getElementById('batchZip').files[0]; if(!f){batchOut.innerHTML='<p class=bad>Select a ZIP first.</p>';return}
 const fd=new FormData(); fd.append('files',f); fd.append('auto_start',document.getElementById('batchAuto').checked?'true':'false');
 batchOut.innerHTML='<div class=find>Importing ZIP...</div>';
 const r=await fetch('/api/batch_import_zip',{method:'POST',body:fd}); const j=await r.json(); batchOut.innerHTML=batchResultHtml(j); await loadProjects();
}
async function batchImportPath(){
 const fd=new FormData(); fd.append('path',document.getElementById('batchPath').value); fd.append('auto_start',document.getElementById('batchPathAuto').checked?'true':'false');
 batchOut.innerHTML='<div class=find>Importing path...</div>';
 const r=await fetch('/api/batch_import_zip_path',{method:'POST',body:fd}); const j=await r.json(); batchOut.innerHTML=batchResultHtml(j); await loadProjects();
}
async function batchSummary(){
 const r=await fetch('/api/batch_summary'); const j=await r.json(); batchOut.innerHTML=batchSummaryHtml(j);
}
async function realbenchManifest(){
 const p=document.getElementById('batchPath').value;
 const r=await fetch('/api/realbench_manifest?path='+encodeURIComponent(p)); const j=await r.json();
 batchOut.innerHTML=`<div class=find><h3>Manifest</h3><p>${j.files?.length||0} files · ${j.challenges?.length||0} challenges</p><pre>${esc(JSON.stringify(j.categories||{},null,2))}</pre>${(j.challenges||[]).slice(0,80).map(c=>`<div class=find><b>${esc(c.category)} / ${esc(c.challenge)}</b><span class=pill>${c.files.length} files</span><span class=pill>${c.total_size} bytes</span></div>`).join("")}</div>`;
}
function batchResultHtml(j){
 if(!j.ok)return `<div class=find><b class=bad>Import failed</b><pre>${esc(JSON.stringify(j,null,2))}</pre></div>`;
 return `<div class=find><h3>Imported ${j.created?.length||0} projects</h3><p>Manifest: ${j.manifest?.challenge_count||0} challenges, ${j.manifest?.file_count||0} files</p>${(j.created||[]).slice(0,120).map(x=>`<div class=find><b>${esc(x.title)}</b><span class=pill>${x.files} files</span><button type=button class=btn onclick="openProject('${x.id}')">open</button></div>`).join("")}</div>`
}
function batchSummaryHtml(j){
 return `<div class=find><h3>Batch Summary</h3><div class=grid3><div class=metric><b>${j.total||0}</b><div class=sub>projects</div></div><div class=metric><b>${j.with_flags||0}</b><div class=sub>with flags</div></div><div class=metric><b>${j.with_answers||0}</b><div class=sub>with answers</div></div><div class=metric><b>${j.unresolved||0}</b><div class=sub>unresolved</div></div></div>${(j.projects||[]).slice(0,200).map(p=>`<div class=find><div class=row><b>${esc(p.title||"")}</b><span class=pill>${esc(p.status||"")}</span><span class=pill>${p.progress||0}%</span><button type=button class=btn onclick="openProject('${p.id}')">open</button></div>${(p.flags||[]).map(f=>`<div class=flag>${esc(f)}</div>`).join("")}${(p.answers||[]).map(a=>`<span class=pill>${esc(a)}</span>`).join("")}</div>`).join("")}</div>`
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>evidence-backed flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${(sum.flag_wrapping_helpers||[]).length}</b><div class=sub>wrapper hints</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>Runs multi-step agents based on real writeups: numeric table static extraction, Piet grid extraction, LSB streams, tile puzzle aids, recursive child artifacts and strict evidence scoring.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,18))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function solveTraceHtml(items){
 if(!items||!items.length)return '<p class=warn>No solve trace yet. Run SLOPER Agents or analyze files.</p>';
 return items.slice(0,700).map(x=>`<div class=find><div class=row><span class=score>${x.confidence||x.score||0}</span><b>${esc(x.stage||x.step||"")}</b><span class=pill>${esc(x.file||"")}</span>${x.flag?`<span class=flag>${esc(x.flag)}</span>`:""}</div><p>${esc(x.detail||"")}</p>${x.artifact?`<button type=button class=btn onclick="copyText('${escAttr(x.artifact)}')">copy artifact path</button> <a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.artifact)}">open</a>`:""}</div>`).join("")
}
function weakFlagsHtml(items){
 if(!items||!items.length)return '<p class=ok>No weak flags. Good: promoted flags require solve evidence.</p>';
 return items.slice(0,160).map(x=>`<div class=find><div class=row><span class=score>${x.support||0}</span><b class=warn>${esc(x.flag||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.flag||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span></div><p class=sub>Not promoted because solve evidence is too weak.</p><p>${(x.sources||[]).map(s=>`<span class=pill>${esc(s)}</span>`).join("")}</p></div>`).join("")
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(sum){
 return `<h3>SLOPER overview</h3>${healthHtml(sum.health||{})}<h3>Answer Candidates</h3>${answerCandidatesHtml(sum.answer_candidates||[])}<h3>High-value artifacts</h3>${artifactsHtml((sum.artifacts||[]).filter(a=>String(a.source||"").includes("SLOPER")||String(a.source||"").includes("VisualForge")||String(a.kind||"").includes("project_brief")))}<h3>Unresolved plan</h3>${unresolvedHtml(sum.unresolved_plan||[])}`
}
function fileSLOPERHtml(f){
 const rb=(f.artifacts||[]).filter(a=>String(a.source||"").includes("SLOPER")||String(a.source||"").includes("VisualForge")||String(a.kind||"").includes("visual")||String(a.kind||"").includes("pcap")||String(a.kind||"").includes("pyc")||String(a.kind||"").includes("decompressed"));
 return `<h3>SLOPER file report</h3><div class=grid3><div class=metric><b>${(f.flags||[]).length}</b><div class=sub>ctf_cs flags</div></div><div class=metric><b>${(f.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${rb.length}</b><div class=sub>realbench artifacts</div></div></div><h3>Answer Candidates</h3>${answerCandidatesHtml(f.answer_candidates||[])}<h3>SLOPER artifacts</h3>${artifactsHtml(rb)}<h3>Visual Lab</h3>${visualLabHtml(rb)}`
}

function answerCandidatesHtml(items){
 if(!items||!items.length)return '<p class=warn>No answer candidates yet. This panel is for non-flag answers too: words, hashes, keys, coordinates, OCR text.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span></div><p><b>Source:</b> ${esc(x.source||"")}</p><p class=sub>${esc(x.why||"")}</p></div>`).join("")
}
function visualLabHtml(items){
 const imgs=(items||[]).filter(a=>String(a.kind||"").includes("visual")||String(a.source||"").includes("SLOPER")||String(a.name||"").match(/channel|threshold|highpass|orientation|contact|posterize|edge|contrast|brightness|solarize|HSV/i));
 if(!imgs.length)return '<p class=warn>No Visual Lab artifacts yet. For image tasks, run/re-run analysis or Run SmartSolve Recipe.</p>';
 return `<div class=gallery>${imgs.slice(0,160).map(a=>`<div class=thumb><a target=_blank href="${a.url||('/api/raw?path='+encodeURIComponent(a.path||''))}"><img src="${a.url||('/api/raw?path='+encodeURIComponent(a.path||''))}"></a><b>${esc(a.name||"")}</b><span class=pill>${a.score||0}</span><button type=button class=btn onclick="copyText('${escAttr(a.path||"")}')">copy path</button></div>`).join("")}</div>`
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>evidence-backed flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${(sum.flag_wrapping_helpers||[]).length}</b><div class=sub>wrapper hints</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>Runs multi-step agents based on real writeups: numeric table static extraction, Piet grid extraction, LSB streams, tile puzzle aids, recursive child artifacts and strict evidence scoring.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,18))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function solveTraceHtml(items){
 if(!items||!items.length)return '<p class=warn>No solve trace yet. Run SLOPER Agents or analyze files.</p>';
 return items.slice(0,700).map(x=>`<div class=find><div class=row><span class=score>${x.confidence||x.score||0}</span><b>${esc(x.stage||x.step||"")}</b><span class=pill>${esc(x.file||"")}</span>${x.flag?`<span class=flag>${esc(x.flag)}</span>`:""}</div><p>${esc(x.detail||"")}</p>${x.artifact?`<button type=button class=btn onclick="copyText('${escAttr(x.artifact)}')">copy artifact path</button> <a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.artifact)}">open</a>`:""}</div>`).join("")
}
function weakFlagsHtml(items){
 if(!items||!items.length)return '<p class=ok>No weak flags. Good: promoted flags require solve evidence.</p>';
 return items.slice(0,160).map(x=>`<div class=find><div class=row><span class=score>${x.support||0}</span><b class=warn>${esc(x.flag||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.flag||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span></div><p class=sub>Not promoted because solve evidence is too weak.</p><p>${(x.sources||[]).map(s=>`<span class=pill>${esc(s)}</span>`).join("")}</p></div>`).join("")
}


function multiStepForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>primary ctf_cs flags</div></div><div class=metric><b>${(sum.alternate_flag_candidates||[]).length}</b><div class=sub>alternate flags</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answers</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>More multi-step agents trained from writeups: timestamp hidden data, QR checkerboard repair, audio/STFT, FWHT/numeric transforms, static web audit, zstd/Scratch extraction, plus previous numeric/Piet/tile/LSB agents.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run SLOPER Agents</button></div><h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,20))}<h3>Alternate flag candidates</h3>${alternateFlagsHtml((sum.alternate_flag_candidates||[]).slice(0,20))}<h3>Evidence Scores</h3>${evidenceScoresHtml((sum.evidence_scored_candidates||[]).slice(0,20))}`
}
function alternateFlagsHtml(items){
 if(!items||!items.length)return '<p class=warn>No alternate-format flags found. This is fine for ctf_cs-only events.</p>';
 return items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span><span class=pill>${esc(x.source||"")}</span></div><p class=sub>${esc(x.why||"alternate flag format candidate")}</p></div>`).join("")
}

function multiStepForgeDashboard(sum){
 const vf=(sum.artifacts||[]).filter(a=>String(a.source||"").includes("SLOPER")||String(a.kind||"").includes("visual"));
 return `<h3>SLOPER overview</h3>${healthHtml(sum.health||{})}<h3>Answer Candidates</h3>${answerCandidatesHtml(sum.answer_candidates||[])}<h3>Visual Lab gallery</h3>${visualLabHtml(vf)}<h3>Project brief</h3>${artifactsHtml((sum.artifacts||[]).filter(a=>String(a.kind||"").includes("project_brief")))}`
}
function fileSLOPERHtml(f){
 const vf=(f.artifacts||[]).filter(a=>String(a.source||"").includes("SLOPER")||String(a.kind||"").includes("visual"));
 const h=f.candidate_health||{};
 return `<h3>SLOPER file report</h3><div class=grid3><div class=metric><b>${(f.flags||[]).length}</b><div class=sub>ctf_cs flags</div></div><div class=metric><b>${(f.answer_candidates||[]).length}</b><div class=sub>answer candidates</div></div><div class=metric><b>${vf.length}</b><div class=sub>visual artifacts</div></div><div class=metric><b>${h.negative_or_noisy_candidates||0}</b><div class=sub>hidden noisy</div></div></div><h3>Answer Candidates</h3>${answerCandidatesHtml(f.answer_candidates||[])}<h3>Visual Lab</h3>${visualLabHtml(vf)}`
}

function healthHtml(h){
 return `<div class=grid3><div class=metric><b>${h.status||"unknown"}</b><div class=sub>status</div></div><div class=metric><b>${h.promoted_flags||0}</b><div class=sub>promoted flags</div></div><div class=metric><b>${h.files_solved||0}/${h.files_total||0}</b><div class=sub>files solved</div></div><div class=metric><b>${h.files_unresolved||0}</b><div class=sub>unresolved</div></div><div class=metric><b>${h.artifacts_total||0}</b><div class=sub>artifacts</div></div><div class=metric><b>${h.hidden_noisy_candidates||0}</b><div class=sub>hidden noisy</div></div></div><p class=sub>Health helps you see whether the project is solved, needs review, or has no signal.</p>`
}
function unresolvedHtml(items){
 if(!items||!items.length)return '<p class=ok>No unresolved files with useful signal.</p>';
 return items.map(x=>`<div class=find><div class=row><b>${esc(x.file||"")}</b><span class=pill>${esc(x.kind||"")}</span><span class=score>${x.best_recipe_score||x.best_chain_score||0}</span></div><p>${esc(x.why_unresolved||"")}</p><p><b>Best recipe:</b> ${esc(x.best_recipe||"")} <span class=pill>${x.best_recipe_score||0}</span></p><p><b>Best artifact:</b> ${esc(x.best_artifact||"")}</p>${x.best_artifact_path?`<button type=button class=btn onclick="copyText('${escAttr(x.best_artifact_path)}')">copy artifact path</button> <a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.best_artifact_path)}">open artifact</a>`:""}<h4>Next actions</h4>${(x.next_actions||[]).map(a=>`<span class=pill>${esc(a)}</span>`).join("")}</div>`).join("")
}
function challengeLabProjectHtml(sum){
 const arts=(sum.artifacts||[]).filter(a=>String(a.kind||"").includes("deeppattern")||String(a.kind||"").includes("project_brief")||String(a.source||"").includes("SLOPER"));
 const rec=(sum.recipes||[]).filter(r=>r.score>=84);
 return `<h3>SLOPER overview</h3>${healthHtml(sum.health||{})}<h3>Project brief</h3>${artifactsHtml((sum.artifacts||[]).filter(a=>String(a.kind||"").includes("project_brief")))}<h3>High-value recipes</h3>${recipesHtml(rec)}<h3>SLOPER artifacts</h3>${artifactsHtml(arts)}<h3>Run local self-checks</h3><button type=button class="btn primary" onclick="runSelfCheck()">Run Self-Check</button><div id=selfCheckOut></div>`
}
function fileSLOPERHtml(f){
 const h=f.candidate_health||{};
 const arts=(f.artifacts||[]).filter(a=>String(a.kind||"").includes("deeppattern")||String(a.source||"").includes("DeepPattern")||String(a.source||"").includes("SLOPER")||String(a.kind||"").includes("lsb_variant")||String(a.kind||"").includes("solver_brief"));
 const deepChains=(f.chain_results||[]).filter(c=>String(c.type||"").includes("deeppattern")).slice(0,60);
 return `<h3>SLOPER file report</h3><div class=grid3><div class=metric><b>${(f.flags||[]).length}</b><div class=sub>promoted</div></div><div class=metric><b>${h.visible_verified_candidates||0}</b><div class=sub>visible verified</div></div><div class=metric><b>${h.negative_or_noisy_candidates||0}</b><div class=sub>hidden noisy</div></div><div class=metric><b>${arts.length}</b><div class=sub>high-value artifacts</div></div><div class=metric><b>${deepChains.length}</b><div class=sub>deep chains</div></div></div><h3>High-value artifacts</h3>${artifactsHtml(arts)}<h3>Deep chains</h3>${deepChains.map(c=>`<details class=cardish><summary><b>${esc(c.type||"chain")}</b> <span class=pill>score ${c.score||0}</span></summary>${(c.flags||[]).map(x=>`<div class=flag>${esc(x)}</div>`).join("")}<pre>${esc(c.output||"")}</pre></details>`).join("")||'<p class=warn>No SLOPER chain results.</p>'}<h3>Recipes</h3>${recipesHtml((f.recipe_runs||[]).map(x=>({...x,file:f.rel,kind:f.kind})).filter(r=>r.score>=84))}`
}
async function runSelfCheck(){
 const box=document.getElementById('selfCheckOut'); if(box)box.innerHTML='<div class=find>Running local self-checks...</div>';
 try{const r=await fetch('/api/self_check',{method:'POST'});const j=await r.json();if(box)box.innerHTML=`<div class=find><h3>Self-check ${j.ok?'passed':'failed'}</h3><p>${j.passed||0}/${j.total||0} passed</p>${(j.results||[]).map(x=>`<div class=find><b class="${x.ok?'ok':'bad'}">${x.ok?'PASS':'FAIL'} ${esc(x.name)}</b><pre>${esc(JSON.stringify(x.flags||[],null,2))}</pre></div>`).join("")}<pre>${esc(j.error||"")}</pre></div>`}catch(e){if(box)box.innerHTML=`<pre>${esc(String(e))}</pre>`}
}

function artifactIcon(kind){kind=String(kind||"");if(kind.includes("preview"))return"";if(kind.includes("pcap"))return"";if(kind.includes("pdf"))return"";if(kind.includes("archive"))return"";if(kind.includes("decoded")||kind.includes("xor"))return"";if(kind.includes("agent"))return"";return""}
function artifactsHtml(items){
 if(!items||!items.length)return '<p class=warn>No artifacts yet. Run analysis or open a file and use Tools / SLOPER.</p>';
 return `<div class=row><input class=search placeholder="Filter artifacts..." oninput="artifactFilter=this.value;renderProject()" value="${escAttr(window.artifactFilter||'')}"></div>`+
 items.filter(a=>!(window.artifactFilter)&&true || (`${a.kind} ${a.name} ${a.file} ${a.source}`.toLowerCase().includes(String(window.artifactFilter||'').toLowerCase()))).slice(0,500).map(a=>`<div class=find><div class=row><span class=score>${a.score||0}</span><b>${artifactIcon(a.kind)} ${esc(a.kind||"artifact")}</b><span class=pill>${esc(a.file||"")}</span><span class=pill>${esc(a.size||0)} bytes</span><span class="${a.exists?'pill ok':'pill bad'}">${a.exists?'exists':'missing'}</span></div><b>${esc(a.name||"")}</b><br><span class=sub>${esc(a.source||"")}</span><p>${esc(a.note||"")}</p><button type=button class=btn onclick="copyText('${escAttr(a.path||"")}')">copy path</button> <a class=btn target=_blank href="${a.url||('/api/raw?path='+encodeURIComponent(a.path||''))}">open raw</a></div>`).join("")
}
function fileArtifactsHtml(f){return `<h3>File artifacts</h3>${artifactsHtml(f.artifacts||[])}`}
function noisyEvidence(x){const v=String((x&&x.value)||'').toLowerCase();const t=String((x&&x.type)||'').toLowerCase();return v.includes('ctf_cs{...}')||v.includes('sample_flag')||v.includes('dummy')||v.includes('placeholder')||v.includes('format is')||(t.includes('partial')&&!(v.includes('ctf_cs{')&&v.includes('}')))}

function verifiedFlagsHtml(items){
 return items.length?items.slice(0,180).map(v=>{
   const neg=(v.negative_reasons||[]).length;
   const cls=v.status==="confirmed"||v.status==="likely"?"ok":(v.status==="low"||neg?"bad":"warn");
   return `<div class=find><div class=row><span class=score>${v.score||0}</span><b class="${cls}">${esc(v.status||"candidate")}</b><code>${esc(v.flag||"")}</code><button type=button class=btn onclick="copyText('${escAttr(v.flag||"")}')">copy</button></div><p><b>Sources:</b> ${(v.sources||[]).map(s=>`<span class=pill>${esc(s)}</span>`).join("")}</p><p><b>Why:</b> ${esc((v.reasons||[]).join("; "))}</p>${neg?`<p class=bad><b>Downgraded:</b> ${esc((v.negative_reasons||[]).join("; "))}</p>`:""}${(v.contexts||[]).slice(0,2).map(c=>`<details class=cardish><summary>context</summary><pre>${esc(c)}</pre></details>`).join("")}</div>`
 }).join(""):'<p class=warn>No verified candidates yet. Random ctf_cs strings are intentionally not promoted unless evidence is strong.</p>'
}
function fileVerifiedFlagsHtml(f){
 return `<h3>Verified flag candidates</h3>${verifiedFlagsHtml(f.verified_flags||[])}<p class=sub>Only confirmed/likely candidates without negative reasons are promoted to Summary flags.</p>`
}

function verifyloopsHtml(items){
 return items.length?items.slice(0,180).map(a=>`<div class=find><div class=row><span class=score>${a.added_outputs||0}</span><b>SLOPER</b><span class=pill>${esc(a.file||"")}</span><span class=pill>${esc(a.kind||"")}</span><span class=pill>${(a.tools||[]).length} tools</span></div><p>Automatically ran relevant Quick+Deep local tools and fed outputs into evidence/decoders/transforms.</p><details class=cardish><summary>Tools run</summary><pre>${esc((a.tools||[]).join("\\n"))}</pre></details></div>`).join(""):'<p class=warn>No SLOPER records yet.</p>'
}
function fileSLOPERHtml(f){
 const a=f.verifyloop||{};
 return `<div class=row><button type=button class="btn primary" onclick="runSLOPER('${escAttr(f.path)}')">Run full SLOPER manually</button></div><div id=verifyloopOut></div><h3>Auto-run summary</h3>${a.tools?`<div class=find><b>${(a.tools||[]).length} tools auto-run</b><br><span class=sub>${a.added_outputs||0} outputs added to analysis</span><details class=cardish><summary>Tools list</summary><pre>${esc((a.tools||[]).join("\\n"))}</pre></details></div>`:'<p class=warn>No SLOPER record yet.</p>'}`
}
async function runSLOPER(path){
 const fd=new FormData(); fd.append('path',path); verifyloopOut.innerHTML='<div class=find>Running full SLOPER: tools → decoders → transforms → agents...</div>';
 const r=await fetch('/api/run_verifyloop',{method:'POST',body:fd}); const j=await r.json();
 verifyloopOut.innerHTML=j.ok?(`<h3>Manual SLOPER · ${esc(j.kind||"")}</h3><h4>Flags</h4>${(j.flags||[]).map(x=>`<div class=flag>${esc(x)} <button type=button class=btn onclick="copyText('${escAttr(x)}')">copy</button></div>`).join("")||'<p class=warn>No exact flag in manual run.</p>'}<h4>Findings</h4>${evidenceBoardHtml(j.findings||[])}<h4>Transformations</h4>${transformsHtml(j.transformations||[])}<h4>Agents</h4>${agentsHtml(j.agents||[])}<h4>Chain results</h4>${decodersBlock(j.chain_results||[])}`):(`<div class=find><b>Error</b><pre>${esc(j.error||JSON.stringify(j,null,2))}</pre></div>`);
}

function transformsHtml(items){
 return items.length?items.slice(0,240).map(t=>`<div class=find><div class=row><span class=score>${t.score||0}</span><b>${esc(t.kind||"transform")}</b><span class=pill>${esc(t.name||"")}</span><span class=pill>${esc(t.file||"")}</span></div><p>${esc(t.note||"")}</p><span class=sub>${esc(t.source||"")}</span><br><button type=button class=btn onclick="copyText('${escAttr(t.path||"")}')">copy path</button> <a class=btn target=_blank href="${t.url||('/api/raw?path='+encodeURIComponent(t.path||''))}">open raw</a></div>`).join(""):'<p class=warn>No transformations yet.</p>'
}
function fileTransformsHtml(f){
 return `<div class=row><button type=button class="btn primary" onclick="runTransforms('${escAttr(f.path)}')">Run SLOPER manually</button></div><div id=transformOut></div><h3>Auto transformations</h3>${transformsHtml((f.transformations||[]).map(x=>({...x,file:f.rel})))}`
}
async function runTransforms(path){
 const fd=new FormData(); fd.append('path',path); transformOut.innerHTML='<div class=find>Running real transformations...</div>';
 const r=await fetch('/api/run_transforms',{method:'POST',body:fd}); const j=await r.json();
 transformOut.innerHTML=j.ok?(`<h3>Manual transformations · ${esc(j.kind||"")}</h3>`+transformsHtml(j.transformations||[])+`<h3>Derived evidence</h3>`+evidenceBoardHtml(j.evidence||[])+`<h3>Derived decoders</h3>`+decodersBlock(j.decoders||[])):(`<div class=find><b>Error</b><pre>${esc(j.error||JSON.stringify(j,null,2))}</pre></div>`);
}

function agentsHtml(items){
 return items.length?items.slice(0,160).map(a=>`<div class=find><div class=row><span class=score>${a.score||0}</span><b>${esc(a.agent||"agent")}</b><span class=pill>${esc(a.title||"")}</span><span class=pill>${esc(a.file||"")}</span></div><p>${esc(a.why||"")}</p><h4>Actions</h4>${(a.actions||[]).map(x=>`<span class=pill>${esc(x)}</span>`).join("")}<h4>Commands</h4>${(a.commands||[]).map(x=>`<span class=pill>${esc(x)}</span>`).join("")}<h4>Evidence</h4>${(a.evidence||[]).slice(0,8).map(e=>`<pre>${esc(typeof e==="string"?e:JSON.stringify(e,null,2))}</pre>`).join("")}</div>`).join(""):'<p class=warn>No agent results yet.</p>'
}
function fileAgentsHtml(f){
 return `<div class=row><button type=button class="btn primary" onclick="runAgents('${escAttr(f.path)}')">Run SLOPER manually</button></div><div id=agentOut></div><h3>Auto agent runs</h3>${agentsHtml((f.agent_runs||[]).map(x=>({...x,file:f.rel})))}<h3>Agent files</h3>${(f.agent_files||[]).length?(f.agent_files||[]).map(x=>`<div class=find><b>${esc(x.name)}</b> <span class=pill>score ${x.score||0}</span><br><span class=sub>${esc(x.source||"")}</span><br><button type=button class=btn onclick="copyText('${escAttr(x.path||"")}')">copy path</button> <a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.path||"")}">open raw</a></div>`).join(""):'<p class=warn>No agent-generated files yet.</p>'}`
}
async function runAgents(path){
 const fd=new FormData(); fd.append('path',path); agentOut.innerHTML='<div class=find>Running SLOPER...</div>';
 const r=await fetch('/api/run_agents',{method:'POST',body:fd}); const j=await r.json();
 agentOut.innerHTML=j.ok?(`<h3>Manual SLOPER result · ${esc(j.kind||"")}</h3>`+agentsHtml(j.agents||[])+`<h3>Hypotheses</h3>`+hypothesesHtml(j.hypotheses||[])):(`<div class=find><b>Error</b><pre>${esc(j.error||JSON.stringify(j,null,2))}</pre></div>`);
}

function hypothesesHtml(items){
 return items.length?items.slice(0,120).map(h=>`<div class=find><div class=row><span class=score>${h.score||0}</span><b>${esc(h.title||"hypothesis")}</b><span class=pill>${esc(h.file||"")}</span><span class=pill>${esc(h.kind||"")}</span></div><p>${esc(h.why||"")}</p><h4>Actions</h4>${(h.actions||[]).map(a=>`<span class=pill>${esc(a)}</span>`).join("")}<h4>Evidence</h4>${(h.evidence||[]).map(e=>`<pre>${esc(typeof e==="string"?e:JSON.stringify(e,null,2))}</pre>`).join("")}</div>`).join(""):'<p class=warn>No hypotheses yet.</p>'
}
function fileHypothesesHtml(f){
 return `<h3>Workflow hypotheses</h3>${hypothesesHtml((f.hypotheses||[]).map(x=>({...x,file:f.rel,kind:f.kind})))}<h3>Structured clues</h3>${(f.structured_clues||[]).length?(f.structured_clues||[]).slice(0,80).map(c=>`<div class=find><span class=score>${c.score||0}</span> <b>${esc(c.type||"clue")}</b><pre>${esc(c.value||"")}</pre><span class=sub>${esc(c.why||"")}</span></div>`).join(""):'<p class=warn>No structured clues detected.</p>'}`
}

function evidenceBoardHtml(items){items=(items||[]).filter(x=>!noisyEvidence(x));return items.length?items.slice(0,180).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.type||"evidence")}</b><span class=pill>${esc(x.file||"")}</span><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button></div><pre>${esc(x.value||"")}</pre><span class=sub>${esc(x.why||"")}</span></div>`).join(""):'<p class=warn>No clean evidence yet. Noisy template/sample candidates are hidden.</p>'}
function workflowStepsHtml(items){return items.length?items.map(x=>`<div class=find><span class=score>${x.priority||0}</span> <b>${esc(x.step||"")}</b> <span class=pill>${esc(x.file||"project")}</span><br><span class=sub>${esc(x.why||"")}</span></div>`).join(""):'<p class=warn>No workflow steps yet.</p>'}
function filesWorkspace(files){let kinds=[...new Set(files.map(f=>f.kind||"generic"))];let shown=files.map((f,i)=>({...f,_idx:i})).filter(f=>(fileKindFilter==="all"||f.kind===fileKindFilter)&&(!fileSearch||(`${f.rel} ${f.kind}`.toLowerCase().includes(fileSearch.toLowerCase()))));return `<div class=row><input class=search placeholder="Search files..." value="${escAttr(fileSearch)}" oninput="fileSearch=this.value;renderProject()"><select onchange="fileKindFilter=this.value;renderProject()"><option value=all>all kinds</option>${kinds.map(k=>`<option value="${escAttr(k)}" ${fileKindFilter===k?'selected':''}>${esc(k)}</option>`).join("")}</select></div><div class=grid2><div class=fileList>${shown.map(f=>`<div class="fileMini ${f._idx===selectedFile?'active':''}" onclick="selectFile(${f._idx})"><b>${esc(f.rel||f.name)}</b><div class=sub>${esc(f.kind)} · ${f.size||0} bytes · entropy ${f.entropy||"?"}</div><span class=pill>${(f.flags||[]).length} flags</span><span class=pill>${(f.findings||[]).length} findings</span><span class=pill>${(f.chain_results||[]).length} chains</span><span class=pill>${(f.artifacts||[]).length} artifacts</span><span class=pill>${(f.intermediate_files||[]).length} intermediates</span></div>`).join("")||'<p class=warn>No files match filter.</p>'}</div><div>${fileDetail(files[selectedFile]||shown[0])}</div></div>`}
function selectFile(i){selectedFile=i;activeFileTab=0;renderProject()}
function fileDetail(f){if(!f)return"<p>No file selected</p>";return `<div class=panel><div class=row between><h3>${esc(f.rel||f.name)}</h3><button type=button class=btn onclick="copyText('${escAttr(f.path||"")}')">copy path</button></div><div class=row><span class=pill>${esc(f.kind)}</span><span class=pill>${f.size||0} bytes</span><span class=pill>entropy ${f.entropy||"?"}</span><span class=pill>${(f.artifacts||[]).length} artifacts</span><span class=pill>${(f.answer_candidates||[]).length} answers</span></div><div class=tabs>${["Summary","AutoPilot","Evidence Scores","Answer Candidates","Flag Wrappers","Artifacts","Visual Lab","Agent Trace","Verified Flags","Recipes","SLOPER","Chain","Intermediates","Preview","Tools","Strings","Decoders","Outputs","Commands"].map((t,k)=>`<button type=button class="${k===activeFileTab?'on':''}" onclick="setFileTab(${k})">${t}</button>`).join("")}</div><div id=filetab0 class="${activeFileTab===0?'':'hidden'}">${fileSummary(f)}</div><div id=filetab1 class="${activeFileTab===1?'':'hidden'}">${answerCandidatesHtml(f.answer_candidates||[])}</div><div id=filetab2 class="${activeFileTab===2?'':'hidden'}">${fileVerifiedFlagsHtml(f)}</div><div id=filetab3 class="${activeFileTab===3?'':'hidden'}">${fileArtifactsHtml(f)}</div><div id=filetab4 class="${activeFileTab===4?'':'hidden'}">${visualLabHtml(f.artifacts||[])}</div><div id=filetab5 class="${activeFileTab===5?'':'hidden'}">${recipesHtml((f.recipe_runs||[]).map(x=>({...x,file:f.rel,kind:f.kind})))}</div><div id=filetab6 class="${activeFileTab===6?'':'hidden'}">${fileSLOPERHtml(f)}</div><div id=filetab7 class="${activeFileTab===7?'':'hidden'}">${artifactGraphHtml([{file:f.rel,graph:f.artifact_graph||{}}])}</div><div id=filetab8 class="${activeFileTab===8?'':'hidden'}">${fileAgentsHtml(f)}</div><div id=filetab9 class="${activeFileTab===9?'':'hidden'}">${fileTransformsHtml(f)}</div><div id=filetab10 class="${activeFileTab===10?'':'hidden'}">${fileHypothesesHtml(f)}</div><div id=filetab11 class="${activeFileTab===11?'':'hidden'}">${chainResultsHtml(f)}</div><div id=filetab12 class="${activeFileTab===12?'':'hidden'}">${intermediatesHtml(f)}</div><div id=filetab13 class="${activeFileTab===13?'':'hidden'}">${previewHtml(f)}</div><div id=filetab14 class="${activeFileTab===14?'':'hidden'}">${toolsHtml(f)}</div><div id=filetab15 class="${activeFileTab===15?'':'hidden'}"><pre>${esc((f.strings||[]).join("\\n"))}</pre></div><div id=filetab16 class="${activeFileTab===16?'':'hidden'}">${decodersHtml(f)}</div><div id=filetab17 class="${activeFileTab===17?'':'hidden'}">${outputsHtml(f)}</div><div id=filetab18 class="${activeFileTab===18?'':'hidden'}"><pre>${esc((f.commands||[]).join("\\n"))}</pre></div></div>`}
function setFileTab(i){activeFileTab=i;renderProject()}
function fileSummary(f){return `<h3>Flags</h3>${(f.flags||[]).map(x=>`<div class=flag>${esc(x)} <button type=button class=btn onclick="copyText('${escAttr(x)}')">copy</button></div>`).join("")||'<p class=warn>No direct flag.</p>'}<h3>Findings</h3>${(f.findings||[]).slice(0,30).map(x=>`<div class=find><span class=score>${x.score||0}</span> <b>${esc(x.type||"finding")}</b><pre>${esc(x.value||"")}</pre><span class=sub>${esc(x.why||"")}</span></div>`).join("")}<h3>Next steps</h3>${(f.next_steps||[]).map(x=>`<div class=find><span class=score>${x.priority||0}</span> <b>${esc(x.step||"")}</b><br><span class=sub>${esc(x.why||"")}</span></div>`).join("")}<h3>Fingerprint</h3><pre>${esc(JSON.stringify(f.fingerprint||{},null,2))}</pre>`}
function chainResultsHtml(f){return (f.chain_results||[]).length?(f.chain_results||[]).slice(0,140).map((c,i)=>`<details class=cardish ${i<12?'open':''}><summary><b>${esc(c.type||"chain")}</b> <span class=pill>score ${c.score||0}</span> <span class=sub>${esc(c.chain_source||"")}</span></summary>${(c.flags||[]).map(x=>`<div class=flag>${esc(x)} <button type=button class=btn onclick="copyText('${escAttr(x)}')">copy</button></div>`).join("")}<pre>${esc(c.output||"")}</pre></details>`).join(""):'<p class=warn>No chain results yet.</p>'}
function intermediatesHtml(f){return (f.intermediate_files||[]).length?(f.intermediate_files||[]).map(x=>`<div class=find><b>${esc(x.name)}</b> <span class=pill>score ${x.score||0}</span><br><span class=sub>${esc(x.source||"")}</span><br><button type=button class=btn onclick="copyText('${escAttr(x.path||"")}')">copy path</button> <a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.path||"")}">open raw</a></div>`).join(""):'<p class=warn>No generated intermediate files yet.</p>'}
function previewHtml(f){return (f.previews||[]).length?`<div class=gallery>${f.previews.map((p,i)=>`<div class="tile ${i<3?'best':''}"><a target=_blank href="${p.url}"><img src="${p.url}"></a><div class=cap><span class=score>score ${p.score||0}</span> · ${esc(p.name)}</div>${(p.flags||[]).map(x=>`<div class=flag>${esc(x)}</div>`).join("")}${p.qr?`<pre>QR:\\n${esc(p.qr)}</pre>`:""}${p.ocr?`<pre>OCR:\\n${esc(p.ocr)}</pre>`:""}</div>`).join("")}</div>`:'<p class=warn>No previews.</p>'}
function toolButtonsFor(f){const base=["file","magic_bytes","strings_braces","strings_utf16","extract_ascii_context","grep_crypto_clues","grep_urls_tokens","find_files_nearby","rg_project","strings","xxd_head","xxd_tail","exiftool","binwalk","binwalk_extract","foremost","yara_basic"];const map={image:["identify","pngcheck","png_chunks","zsteg_all","stegseek","steghide_info","steghide_extract_empty","tesseract","zbarimg","binwalk_recursive"],pcap:["capinfos","tshark_protocols","tshark_http","tshark_dns","tshark_tcp0","tshark_tcp1","tshark_tcp2","tshark_files"],pdf:["pdfinfo","pdftotext","pdfimages","pdfdetach_list","pdfdetach_extract","qpdf_check"],archive:["seven_list","zipinfo","zip_comment","hashid_file","binwalk_recursive"],binary:["readelf","elf_sections","elf_imports","checksec_basic","rabin2_info","rabin2_strings","r2_info","upx_test","upx_decompress","objdump","objdump_rodata","nm","ltrace_short","strace_short"],media:["ffprobe","soxi","spectrogram"],sqlite:["sqlite_tables","sqlite_schema"],apk:["apktool_decode","jadx_decompile"],python_bytecode:["python_pyc_decompile","decompyle3"]};return [...new Set([...base,...(map[f.kind]||[])])]}
function toolsHtml(f){const key=f.path||f.rel||'';return `<div class=row><button type=button class="btn primary" onclick="runSuite('${escAttr(f.path)}','quick')">Run Quick Suite</button><button type=button class="btn primary" onclick="runSuite('${escAttr(f.path)}','deep')">Run Deep Suite</button><button type=button class="btn primary" onclick="runSmartRecipe('${escAttr(f.path)}')">Run SLOPER Recipe</button><button type=button class=btn onclick="manualResults['${escAttr(f.path)}']='';renderProject()">clear output</button></div><h3>Manual local tools</h3><div class=tools>${toolButtonsFor(f).map(t=>`<button type=button class=btn onclick="runTool('${escAttr(f.path)}','${t}')">${t}</button>`).join("")}</div><div id=toolOut>${manualResults[key]||''}</div>`}
function decodersHtml(f){return (f.decoders||[]).length?(f.decoders||[]).slice(0,160).map((d,i)=>`<details class=cardish ${i<12?'open':''}><summary><b>${esc(d.type)}</b> <span class=pill>score ${d.score||0}</span></summary>${(d.flags||[]).map(x=>`<div class=flag>${esc(x)} <button type=button class=btn onclick="copyText('${escAttr(x)}')">copy</button></div>`).join("")}<pre>${esc(d.output)}</pre></details>`).join(""):'<p class=warn>No decoder hits.</p>'}
function outputsHtml(f){return (f.outputs||[]).map((o,i)=>`<details class=cardish ${i<8?'open':''}><summary><b>${esc(o.tool)}</b> ${o.ok?'<span class="pill ok">ok</span>':'<span class="pill bad">fail/missing</span>'}</summary><div class=sub>${esc(o.cmd||"")}</div><pre>${esc(o.out||"")}</pre></details>`).join("")||'<p class=warn>No outputs.</p>'}
async function runTool(path,toolname){uiBusy=true;const fd=new FormData();fd.append('path',path);fd.append('toolname',toolname);manualResults[path]='<div class=find>Running '+esc(toolname)+'...</div>';renderProject();try{const r=await fetch('/api/run_tool',{method:'POST',body:fd});const j=await r.json();manualResults[path]=toolResultHtml(j)}catch(e){manualResults[path]=`<div class=find><b>Tool error</b><pre>${esc(String(e))}</pre></div>`}uiBusy=false;renderProject()}
async function runSuite(path,suite){uiBusy=true;const fd=new FormData();fd.append('path',path);fd.append('suite',suite);manualResults[path]='<div class=find>Running '+esc(suite)+' suite...</div>';renderProject();try{const r=await fetch('/api/run_tool_suite',{method:'POST',body:fd});const j=await r.json();manualResults[path]=suiteResultHtml(j)}catch(e){manualResults[path]=`<div class=find><b>Suite error</b><pre>${esc(String(e))}</pre></div>`}uiBusy=false;renderProject()}
function toolResultHtml(j){return `<div class=card><h3>${esc(j.tool||"tool")} ${j.ok?'<span class="pill ok">ok</span>':'<span class="pill bad">failed/missing</span>'}</h3><div class=sub>${esc(j.cmd||"")}</div>${(j.missing||[]).length?`<div class=find><b>Missing:</b> ${esc((j.missing||[]).join(", "))}<br>${esc(j.install_hint||"Run FULL_INSTALL.sh")}</div>`:""}${evidenceBoardHtml(j.evidence||[])}${decodersBlock(j.decoders||[])}<pre>${esc(j.out||"")}</pre></div>`}
function suiteResultHtml(j){return `<div class=card><h3>${esc(j.suite||"suite")} suite · ${esc(j.kind||"")}</h3><h4>Derived evidence</h4>${evidenceBoardHtml((j.derived||{}).evidence||[])}${decodersBlock((j.derived||{}).decoders||[])}<h4>Tool results</h4>${(j.results||[]).map(toolResultHtml).join("")}</div>`}
function decodersBlock(items){return items.length?items.slice(0,40).map(d=>`<details class=cardish><summary><b>${esc(d.type)}</b> <span class=pill>score ${d.score||0}</span></summary>${(d.flags||[]).map(x=>`<div class=flag>${esc(x)}</div>`).join("")}<pre>${esc(d.output||"")}</pre></details>`).join(""):""}
function projectChat(pid){return `<div class=card><h3>Project Notes</h3><p class=sub>The assistant panel is disabled in FINAL. Use Open First, Flags, Transforms, Files and Logs. The project context can still be copied for your own notes.</p><button type=button class=btn onclick="copyProjectPrompt()">copy project context</button><pre>${esc(projectPrompt||'')}</pre></div>`}
async function askProjectAI(pid){copyProjectPrompt();alert('Assistant panel is disabled in FINAL. Project context copied instead.')}
async function decodeNow(){const fd=new FormData();fd.append('text',decodeText.value);const r=await fetch('/api/decode',{method:'POST',body:fd});const j=await r.json();decodeOut.innerHTML=decodersBlock(j.items||[])}
async function checkTools(){const r=await fetch('/api/tool_status');const j=await r.json();let h='<h3>Command-backed tools</h3>';h+=(j.tools||[]).map(t=>`<span class="pill ${t.installed?'ok':'bad'}">${t.installed?'':''} ${esc(t.name)}${t.missing&&t.missing.length?' missing '+esc(t.missing.join(',')):''}</span>`).join("");h+='<h3>Virtual workflow profiles</h3><p class=sub>These profiles are represented by suites/agents and mapped to local tools when relevant.</p>';h+=(j.virtual_profiles||[]).slice(0,300).map(x=>`<span class=pill>${esc(x)}</span>`).join("");toolsOut.innerHTML=h}
async function setup(a){const fd=new FormData();fd.append('action',a);const r=await fetch('/api/setup',{method:'POST',body:fd});const j=await r.json();setupOut.textContent=j.out||JSON.stringify(j,null,2)}
function copyProjectPrompt(){navigator.clipboard.writeText(projectPrompt);prompt.value=projectPrompt}
function sendProjectAI(){copyProjectPrompt();alert('Assistant panel is disabled in FINAL. Project context copied instead.')}
async function askAI(){alert('Assistant panel is disabled in FINAL.')}
function copyText(s){navigator.clipboard.writeText(String(s||""))}
function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function escAttr(s){return esc(s).replace(/'/g,'&#39;').replace(/\n/g,' ')}
loadProjects();setInterval(()=>{if(!document.getElementById('projects').classList.contains('hidden'))loadProjects()},6000)

/* ==================== v72 SLOPER UI overrides ==================== */
function uxTabs(){
 const groups=[
  ["Solve",["Dashboard","Solve Trace","AutoPilot","Evidence","Answers","Raw Answers","Wrappers","Weak Flags"]],
  ["Review",["Artifacts","Visual Lab","Verified","Unresolved","Recipes"]],
  ["Work",["Files","Notes","Logs"]]
 ];
 let i=0;
 return groups.map(g=>`<span class=groupLabel>${g[0]}</span>`+g[1].map(t=>`<button type=button class="${i===activeProjectTab?'on':''}" onclick="setProjectTab(${i++})">${t}</button>`).join("")).join("")
}
function uxProjectMetrics(sum,files,job){
 return `<div class=grid3><div class=metric><b>${job.progress||0}%</b><div class=sub>progress</div></div><div class=metric><b>${files.length}</b><div class=sub>files</div></div><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>ctf_cs flags</div></div><div class=metric><b>${(sum.raw_answer_candidates||[]).length}</b><div class=sub>raw answers</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>candidates</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div></div>`
}
function renderProject(){
 const j=currentData,rep=j.report||{},meta=j.project||{},job=j.job||{},files=rep.files||[],sum=rep.summary||{};
 if(selectedFile>=files.length)selectedFile=0; projectPrompt=rep.ai_prompt||"";
 projectView.innerHTML=`<div class=card><div class=row between><div><h2>${esc(meta.title||"Project")}</h2><div class=sub>${esc(meta.category||"")} · ${esc(meta.id||"")}</div></div><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve Agents</button></div>${uxProjectMetrics(sum,files,job)}<div class=progress><div class=bar style="width:${job.progress||0}%"></div></div><div class=row><span class=pill>${esc(job.stage||"")}</span>${Object.entries(sum.kinds||{}).map(([k,v])=>`<span class=pill>${esc(k)}:${v}</span>`).join("")}</div></div><div class=card><div class=tabs>${uxTabs()}</div><div class=compactNavNote>Primary promoted flag format: <b>ctf_cs{...}</b>. Other raw answers stay separate until the task statement says no wrapper.</div><div id=proj0 class="${activeProjectTab===0?'':'hidden'}">${uxForgeDashboard(meta,sum)}</div><div id=proj1 class="${activeProjectTab===1?'':'hidden'}">${solveTraceHtml(sum.solve_trace||[])}</div><div id=proj2 class="${activeProjectTab===2?'':'hidden'}">${autoPilotReviewHtml(sum.autopilot_reviews||[])}</div><div id=proj3 class="${activeProjectTab===3?'':'hidden'}">${evidenceScoresHtml(sum.evidence_scored_candidates||[])}</div><div id=proj4 class="${activeProjectTab===4?'':'hidden'}">${answerCandidatesHtml(sum.answer_candidates||[])}</div><div id=proj5 class="${activeProjectTab===5?'':'hidden'}">${rawAnswersHtml(sum.raw_answer_candidates||[])}</div><div id=proj6 class="${activeProjectTab===6?'':'hidden'}">${flagWrappersHtml(sum.flag_wrapping_helpers||[])}</div><div id=proj7 class="${activeProjectTab===7?'':'hidden'}">${weakFlagsHtml(sum.weak_flag_candidates||[])}</div><div id=proj8 class="${activeProjectTab===8?'':'hidden'}">${artifactsHtml(sum.artifacts||[])}</div><div id=proj9 class="${activeProjectTab===9?'':'hidden'}">${visualLabHtml(sum.artifacts||[])}</div><div id=proj10 class="${activeProjectTab===10?'':'hidden'}">${verifiedFlagsHtml(sum.verified_flags||[])}</div><div id=proj11 class="${activeProjectTab===11?'':'hidden'}">${unresolvedHtml(sum.unresolved_plan||[])}</div><div id=proj12 class="${activeProjectTab===12?'':'hidden'}">${recipesHtml(sum.recipes||[])}</div><div id=proj13 class="${activeProjectTab===13?'':'hidden'}">${filesWorkspace(files)}</div><div id=proj14 class="${activeProjectTab===14?'':'hidden'}">${projectChat(meta.id)}</div><div id=proj15 class="${activeProjectTab===15?'':'hidden'}"><pre>${esc(j.log||"")}</pre></div></div>`
}
function uxForgeDashboard(meta,sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>ctf_cs flags</div></div><div class=metric><b>${(sum.raw_answer_candidates||[]).length}</b><div class=sub>raw answers</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak flags</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve steps</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${(sum.flag_wrapping_helpers||[]).length}</b><div class=sub>wrapper hints</div></div></div><div class=find><h3>SLOPER AutoSolve</h3><p class=sub>Multi-step agents: numeric tables, Piet grids, tile puzzles, LSB streams, timestamp clues, QR repair, audio/STFT, FWHT transforms, static web audit and recursive artifacts.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve Agents</button></div><h3>Best ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No evidence-backed ctf_cs flag yet.</p>'}<h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,12))}<h3>Top artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,12))}`
}
function rawAnswersHtml(items){
 if(!items||!items.length)return '<p class=warn>No raw answers. Usually you should submit ctf_cs{...}; raw answers appear only when the statement hints no wrapper.</p>';
 return items.slice(0,120).map(x=>`<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(x.value||"")}</b><button type=button class=btn onclick="copyText('${escAttr(x.value||"")}')">copy</button><span class=pill>${esc(x.file||"")}</span></div><p class=sub>${esc(x.why||"raw answer candidate")}</p></div>`).join("")
}
function artifactsHtml(items){
 if(!items||!items.length)return '<p class=warn>No artifacts yet. Run analysis or AutoSolve agents.</p>';
 const f=String(window.artifactFilter||'').toLowerCase();
 const shown=items.filter(a=>!f || (`${a.kind} ${a.name} ${a.file} ${a.source} ${a.note}`.toLowerCase().includes(f))).slice(0,600);
 return `<div class=visualToolbar><input class=search placeholder="Filter artifacts..." oninput="artifactFilter=this.value;renderProject()" value="${escAttr(window.artifactFilter||'')}"><span class=pill>${shown.length}/${items.length}</span></div><div class=artifactGrid>${shown.map(a=>`<div class=artifactCard><div class=row><span class=score>${a.score||0}</span><span class=pill>${esc(a.kind||"artifact")}</span><span class=pill>${esc(a.file||"")}</span></div><h4>${artifactIcon(a.kind)} ${esc(a.name||"")}</h4><div class=sub>${esc(a.source||"")} · ${esc(a.size||0)} bytes · ${a.exists?'exists':'missing'}</div><p>${esc(a.note||"")}</p><div class=actions><button type=button class=btn onclick="copyText('${escAttr(a.path||"")}')">copy path</button><a class=btn target=_blank href="${a.url||('/api/raw?path='+encodeURIComponent(a.path||''))}">open</a></div></div>`).join("")}</div>`
}
function visualLabHtml(items){
 const imgs=(items||[]).filter(a=>String(a.kind||"").match(/visual|image|piet|tile|qr|lsb|channel|threshold|contact|edge|posterize|orientation|checkerboard/i)||String(a.name||"").match(/\.(png|jpg|jpeg|gif|webp|bmp)$/i)||String(a.name||"").match(/channel|threshold|highpass|orientation|contact|posterize|edge|contrast|brightness|solarize|HSV|qr|piet|tile|lsb/i));
 if(!imgs.length)return '<p class=warn>No Visual Lab artifacts yet. For image tasks, run AutoSolve Agents.</p>';
 const f=String(window.visualFilter||'').toLowerCase();
 const shown=imgs.filter(a=>!f || (`${a.kind} ${a.name} ${a.note} ${a.file}`.toLowerCase().includes(f))).slice(0,240);
 return `<div class=visualToolbar><input class=search placeholder="Filter visual outputs..." oninput="visualFilter=this.value;renderProject()" value="${escAttr(window.visualFilter||'')}"><span class=pill>${shown.length}/${imgs.length}</span><button type=button class=btn onclick="visualFilter='';renderProject()">clear</button></div><div class=gallery>${shown.map(a=>`<div class=thumb><a target=_blank href="${a.url||('/api/raw?path='+encodeURIComponent(a.path||''))}"><img loading=lazy src="${a.url||('/api/raw?path='+encodeURIComponent(a.path||''))}"></a><b>${esc(a.name||"")}</b><span class=pill>${esc(a.kind||"")}</span><span class=pill>score ${a.score||0}</span><button type=button class=btn onclick="copyText('${escAttr(a.path||"")}')">copy path</button></div>`).join("")}</div>`
}
/* ==================== end v72 SLOPER UI overrides ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps clean UI overrides ==================== */
function artifactIcon(kind){
 const k=String(kind||"").toLowerCase();
 if(k.includes("pcap")) return "[PCAP]";
 if(k.includes("image")||k.includes("visual")||k.includes("qr")||k.includes("piet")||k.includes("tile")) return "[IMG]";
 if(k.includes("zip")||k.includes("archive")||k.includes("embedded")||k.includes("carved")) return "[CARVE]";
 if(k.includes("pyc")||k.includes("reverse")||k.includes("binary")) return "[REV]";
 if(k.includes("text")||k.includes("decoded")) return "[TEXT]";
 if(k.includes("time")||k.includes("log")) return "[LOG]";
 return "[ART]";
}
function sloperStatusPanel(sum){
 return `<div class=grid3><div class=metric><b>${(sum.flags||[]).length}</b><div class=sub>promoted flags</div></div><div class=metric><b>${(sum.answer_candidates||[]).length}</b><div class=sub>answer candidates</div></div><div class=metric><b>${(sum.flag_wrapping_helpers||[]).length}</b><div class=sub>wrapper hints</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${(sum.solve_trace||[]).length}</b><div class=sub>solve trace steps</div></div><div class=metric><b>${(sum.weak_flag_candidates||[]).length}</b><div class=sub>weak candidates</div></div></div>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>Evidence-first local CTF workflow. The solver prioritizes carving, decompression, reverse immediate arrays, PCAP scalar fields, PYC constants, log reconstruction and route/transposition workflows before expensive brute force.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div><h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No promoted ctf_cs flag yet. Check Solve Trace, Artifacts and Wrapper Hints.</p>'}<h3>Next workflow</h3>${workflowStepsHtml(sum.workflow_steps||[])}<h3>Top solve trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,12))}<h3>Priority artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,12))}`
}
function uxTabs(){
 const groups=[
  ["Solve",["Dashboard","Trace","Autopilot","Evidence","Answers","Raw","Wrappers","Weak"]],
  ["Review",["Artifacts","Visual","Verified","Unresolved","Recipes"]],
  ["Work",["Files","Notes","Logs"]]
 ];
 let i=0;
 return groups.map(g=>`<span class=groupLabel>${g[0]}</span>`+g[1].map(t=>`<button type=button class="${i===activeProjectTab?'on':''}" onclick="setProjectTab(${i++})">${t}</button>`).join("")).join("")
}
function artifactsHtml(items){
 if(!items||!items.length)return '<p class=warn>No artifacts yet. Run analysis or AutoSolve.</p>';
 const f=String(window.artifactFilter||'').toLowerCase();
 const shown=items.filter(a=>!f || (`${a.kind} ${a.name} ${a.file} ${a.source} ${a.note}`.toLowerCase().includes(f))).slice(0,700);
 return `<div class=visualToolbar><input class=search placeholder="Filter artifacts by kind, filename, source..." oninput="artifactFilter=this.value;renderProject()" value="${escAttr(window.artifactFilter||'')}"><span class=pill>${shown.length}/${items.length}</span></div><div class=artifactGrid>${shown.map(a=>`<div class=artifactCard><div class=row><span class=score>${a.score||0}</span><span class=pill>${esc(a.kind||"artifact")}</span><span class=pill>${esc(a.file||"")}</span></div><h4>${artifactIcon(a.kind)} ${esc(a.name||"")}</h4><div class=sub>${esc(a.source||"")} · ${esc(a.size||0)} bytes · ${a.exists?'exists':'missing'}</div><p>${esc(a.note||"")}</p><div class=actions><button type=button class=btn onclick="copyText('${escAttr(a.path||"")}')">copy path</button><a class=btn target=_blank href="${a.url||('/api/raw?path='+encodeURIComponent(a.path||''))}">open</a></div></div>`).join("")}</div>`
}
/* ==================== end CTF SLOPER v77 Strict Wraps clean UI overrides ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloperNextActionsHtml(items){
 if(!items||!items.length)return '<p class=warn>No next actions yet. Run AutoSolve first.</p>';
 return items.slice(0,10).map(x=>`<div class=find><div class=row><span class=score>${x.priority||0}</span><b>${esc(x.step||"")}</b></div><p class=sub>${esc(x.why||"")}</p></div>`).join("")
}
function sloperProjectCluesHtml(items){
 if(!items||!items.length)return '<p class=warn>No project-level password/key clues found yet.</p>';
 return `<div class=artifactGrid>${items.slice(0,80).map(x=>`<div class=artifactCard><div class=row><span class=score>${x.score||0}</span><span class=pill>${esc(x.source||"clue")}</span></div><h4>[CLUE] ${esc(x.value||"")}</h4></div>`).join("")}</div>`
}
function sloperTargetsHtml(items){
 if(!items||!items.length)return '<p class=warn>No archive/stego targets detected yet.</p>';
 return `<div class=artifactGrid>${items.slice(0,80).map(a=>`<div class=artifactCard><div class=row><span class=score>${a.score||0}</span><span class=pill>${esc(a.kind||"target")}</span></div><h4>[TARGET] ${esc(a.name||"")}</h4><p class=sub>${esc(a.note||"")}</p><div class=actions><a class=btn target=_blank href="${a.url||('/api/raw?path='+encodeURIComponent(a.path||''))}">open</a><button type=button class=btn onclick="copyText('${escAttr(a.path||"")}')">copy path</button></div></div>`).join("")}</div>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 focuses on project-level solving: clue passwords, archive targets, PCAP covert channels, stego password propagation, recursive decode chains and evidence-backed ctf_cs promotion.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div><h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No promoted ctf_cs flag yet. Check Next Actions, Trace and Artifacts.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper42_next_actions||sum.workflow_steps||[])}<h3>Project Clues</h3>${sloperProjectCluesHtml(sum.sloper42_project_clues||[])}<h3>Archive / Stego Targets</h3>${sloperTargetsHtml(sum.sloper42_archive_targets||[])}<h3>Top Trace</h3>${solveTraceHtml((sum.solve_trace||[]).slice(0,12))}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,12))}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions forced ==================== */
function sloperEvidenceTimelineHtml(items){
 if(!items||!items.length)return '<p class=warn>No evidence timeline yet. Run AutoSolve first.</p>';
 return items.slice(0,80).map(x=>`<div class=find><div class=row><span class=score>${x.confidence||0}</span><b>${esc(x.stage||"")}</b><span class=pill>${esc(x.file||"")}</span></div><p>${esc(x.detail||"")}</p>${x.flag?`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button></div>`:''}${x.artifact?`<div class=actions><a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.artifact)}">open artifact</a><button type=button class=btn onclick="copyText('${escAttr(x.artifact)}')">copy path</button></div>`:''}</div>`).join("")
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 adds recursive child-artifact autopass, stronger decode chains, XOR/RSA/Caesar helpers and an evidence timeline. Extracted files are re-analyzed as real files when useful.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div><h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No promoted ctf_cs flag yet. Check Evidence Timeline, Next Actions and Artifacts.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper43_next_actions||sum.sloper42_next_actions||sum.workflow_steps||[])}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}<h3>Project Clues</h3>${sloperProjectCluesHtml(sum.sloper42_project_clues||[])}<h3>Archive / Stego Targets</h3>${sloperTargetsHtml(sum.sloper42_archive_targets||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,16))}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions forced ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions forced ==================== */
function sloper44CapsHtml(caps){
 caps=caps||{};
 const rows=[
  ["Reverse artifacts",caps.reverse||0],
  ["Stego/Image artifacts",caps.stego_image||0],
  ["Crypto artifacts",caps.crypto||0],
  ["Autopass artifacts",caps.autopass||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${r[1]}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 strengthens reversing, stego-after-transformation, misc and crypto workflows. New agents add cmp/immediate recovery, byte-array pairwise transforms, image transform OCR/QR, rail/every-nth/Bacon/Vigenere and recursive evidence artifacts.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div><h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No promoted ctf_cs flag yet. Check Evidence Timeline, v72 Artifacts and Wrappers.</p>'}<h3>v72 Capability Hits</h3>${sloper44CapsHtml(sum.sloper44_capability_hits||{})}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper44_next_actions||sum.sloper43_next_actions||sum.sloper42_next_actions||sum.workflow_steps||[])}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}<h3>Project Clues</h3>${sloperProjectCluesHtml(sum.sloper42_project_clues||[])}<h3>Archive / Stego Targets</h3>${sloperTargetsHtml(sum.sloper42_archive_targets||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,18))}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions forced ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions forced ==================== */
function sloper45CapsHtml(caps){
 caps=caps||{};
 const rows=[
  ["Archive chain artifacts",caps.archive_chain||0],
  ["EXIF/Morse clues",caps.exif_morse||0],
  ["Embedded ZIP/password artifacts",caps.embedded_zip_password||0],
  ["Reverse artifacts",caps.reverse||0],
  ["Stego/Image artifacts",caps.stego_image||0],
  ["Crypto artifacts",caps.crypto||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${r[1]}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 strengthens archive/stego chains: TGZ/TAR extraction, EXIF comment Morse clues, encrypted embedded ZIP passwords and FLAG marker wrapping.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div><h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No promoted ctf_cs flag yet. Check Evidence Timeline, v72 Artifacts and Wrappers.</p>'}<h3>v72 Capability Hits</h3>${sloper45CapsHtml(sum.sloper45_capability_hits||sum.sloper44_capability_hits||{})}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper45_next_actions||sum.sloper44_next_actions||sum.sloper43_next_actions||sum.workflow_steps||[])}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}<h3>Project Clues</h3>${sloperProjectCluesHtml(sum.sloper42_project_clues||[])}<h3>Archive / Stego Targets</h3>${sloperTargetsHtml(sum.sloper42_archive_targets||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,18))}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions forced ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloper46CapsHtml(caps){
 caps=caps||{};
 const rows=[
  ["Cardan/Fleissner artifacts",caps.cardan_grille||0],
  ["SHA256 answer traces",caps.sha256_answers||0],
  ["PCAP exports",caps.pcap_exports||0],
  ["Archive chain artifacts",caps.archive_chain||0],
  ["EXIF/Morse clues",caps.exif_morse||0],
  ["Embedded ZIP/password artifacts",caps.embedded_zip_password||0],
  ["Reverse artifacts",caps.reverse||0],
  ["Stego/Image artifacts",caps.stego_image||0],
  ["Crypto artifacts",caps.crypto||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${r[1]}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 strengthens multi-file solving: Cardan/Fleissner message+key grids, SHA256 answer tasks, PCAP object export and stricter placeholder suppression.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div><h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No promoted ctf_cs flag yet. Check Evidence Timeline, v72 Artifacts and Wrappers.</p>'}<h3>v72 Capability Hits</h3>${sloper46CapsHtml(sum.sloper46_capability_hits||sum.sloper45_capability_hits||{})}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper46_next_actions||sum.sloper45_next_actions||sum.sloper44_next_actions||sum.workflow_steps||[])}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}<h3>Project Clues</h3>${sloperProjectCluesHtml(sum.sloper42_project_clues||[])}<h3>Archive / Stego Targets</h3>${sloperTargetsHtml(sum.sloper42_archive_targets||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,18))}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloper47ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Status",lane.status||"unknown"],
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrapper candidates",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["Files analyzed",lane.files_analyzed||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function sloper47HealthHtml(h){
 h=h||{};
 return `<div class=find><h3>Project Health</h3><p>${esc(h.advice||"Promoted Flags are strict. Wrappers are candidates. Artifacts show evidence and manual next steps.")}</p>${h.warning?`<p class=warn>${esc(h.warning)}</p>`:""}</div>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 focuses on human usability: bounded TXT/LOG fast paths, noise-filtered artifact reconstruction, time anomaly reports, cleaner review lanes and stricter flag promotion.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div><h3>Review Lanes</h3>${sloper47ReviewLanesHtml(sum.sloper47_review_lanes||{})}${sloper47HealthHtml(sum.sloper47_project_health||{})}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check Wrappers and Priority Artifacts.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper47_next_actions||sum.sloper46_next_actions||sum.workflow_steps||[])}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,20))}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,12).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloper48ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Status",lane.status||"unknown"],
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrapper candidates",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["Image LSB artifacts",lane.v72_image_lsb_artifacts||0],
  ["Palette artifacts",lane.v72_palette_artifacts||0],
  ["PCAP artifacts",lane.v72_pcap_artifacts||0],
  ["Files analyzed",lane.files_analyzed||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 adds startup self-check, image LSB/palette artifacts, PCAP field fallback extraction and stricter promoted flag cleanup. Promoted Flags are strict; Wrappers are candidates; Artifacts are evidence.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div><h3>Review Lanes</h3>${sloper48ReviewLanesHtml(sum.sloper48_review_lanes||sum.sloper47_review_lanes||{})}${sloper47HealthHtml(sum.sloper47_project_health||{})}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check Wrappers and Priority Artifacts.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper48_next_actions||sum.sloper47_next_actions||sum.workflow_steps||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,24))}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,16).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloper49BriefHtml(b){
 b=b||{};
 const fam=b.artifact_families||{};
 const famRows=Object.keys(fam).sort().map(k=>`<span class=pill>${esc(k)}: ${esc(String(fam[k]))}</span>`).join(" ");
 return `<div class=find><h3>Project Brief</h3><div class=row><span class=score>${esc(b.status||"unknown")}</span><b>${esc(b.inspect_first||"Review artifacts")}</b></div><p class=sub>Promoted flags: ${esc(String(b.promoted_flags||0))} · Wrappers: ${esc(String(b.wrapper_candidates||0))} · Priority artifacts: ${esc(String(b.priority_artifacts||0))}</p><p>${famRows||'<span class=pill>no artifacts yet</span>'}</p>${b.warning?`<p class=warn>${esc(b.warning)}</p>`:""}</div>`
}
function sloper49ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Status",lane.status||"unknown"],
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrapper candidates",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["v72 visual artifacts",lane.v72_visual_artifacts||0],
  ["v72 text decode artifacts",lane.v72_text_decode_artifacts||0],
  ["Image LSB artifacts",lane.v72_image_lsb_artifacts||lane.v48_image_lsb_artifacts||0],
  ["PCAP artifacts",lane.v72_pcap_artifacts||lane.v48_pcap_artifacts||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 focuses on human review and practical solving: visual contact sheets, selected OCR/QR, fast text decode artifacts, project brief and stricter promoted flag behavior.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div>${sloper49BriefHtml(sum.sloper49_project_brief||{})}<h3>Review Lanes</h3>${sloper49ReviewLanesHtml(sum.sloper49_review_lanes||sum.sloper48_review_lanes||sum.sloper47_review_lanes||{})}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check Priority Artifacts and Wrappers.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper49_next_actions||sum.sloper48_next_actions||sum.workflow_steps||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,28))}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,18).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloper50BriefHtml(b){
 b=b||{};
 const fam=b.artifact_families||{};
 const famRows=Object.keys(fam).sort().map(k=>`<span class=pill>${esc(k)}: ${esc(String(fam[k]))}</span>`).join(" ");
 return `<div class=find><h3>Project Brief</h3><div class=row><span class=score>${esc(b.status||"unknown")}</span><b>${esc(b.inspect_first||"Review artifacts")}</b></div><p class=sub>Promoted flags: ${esc(String(b.promoted_flags||0))} · Wrappers: ${esc(String(b.wrapper_candidates||0))} · Priority artifacts: ${esc(String(b.priority_artifacts||0))}</p><p class=sub>v72 transformation pipeline: ${esc(b.v72_transformation_pipeline||"not run")}</p><p>${famRows||'<span class=pill>no artifacts yet</span>'}</p>${b.warning?`<p class=warn>${esc(b.warning)}</p>`:""}</div>`
}
function sloper50ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Status",lane.status||"unknown"],
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrapper candidates",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["v72 transformed children",lane.v72_transformed_children||0],
  ["v72 transform graphs",lane.v72_transform_graphs||0],
  ["v49 visual artifacts",lane.v72_visual_artifacts||lane.v49_visual_artifacts||0],
  ["Text decode artifacts",lane.v72_text_decode_artifacts||lane.v49_text_decode_artifacts||0],
  ["PCAP artifacts",lane.v72_pcap_artifacts||lane.v48_pcap_artifacts||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 adds a transformation-first pipeline: XOR/ADD/SUB/NOT/ROL/ROR transforms become child files, child files are analyzed, and transform_graph.json shows the path.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div>${sloper50BriefHtml(sum.sloper50_project_brief||sum.sloper49_project_brief||{})}<h3>Review Lanes</h3>${sloper50ReviewLanesHtml(sum.sloper50_review_lanes||sum.sloper49_review_lanes||{})}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check transform_graph.json, Priority Artifacts and Wrappers.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper50_next_actions||sum.sloper49_next_actions||sum.workflow_steps||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,32))}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,18).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloper51BriefHtml(b){
 b=b||{};
 const fam=b.artifact_families||{};
 const famRows=Object.keys(fam).sort().map(k=>`<span class=pill>${esc(k)}: ${esc(String(fam[k]))}</span>`).join(" ");
 return `<div class=find><h3>Project Brief</h3><div class=row><span class=score>${esc(b.status||"unknown")}</span><b>${esc(b.inspect_first||"Review artifacts")}</b></div><p class=sub>Promoted flags: ${esc(String(b.promoted_flags||0))} · Wrappers: ${esc(String(b.wrapper_candidates||0))} · Priority artifacts: ${esc(String(b.priority_artifacts||0))}</p><p class=sub>v72 coverage: ${esc(b.v72_coverage||"not active")}</p><p>${famRows||'<span class=pill>no artifacts yet</span>'}</p>${b.warning?`<p class=warn>${esc(b.warning)}</p>`:""}</div>`
}
function sloper51ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Status",lane.status||"unknown"],
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrapper candidates",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["v72 PYC backdoor",lane.v72_pyc_backdoor||0],
  ["v72 recursive ZIP",lane.v72_recursive_zip||0],
  ["v72 pure PCAP",lane.v72_pure_pcap||0],
  ["v72 PNG streams",lane.v72_png_streams||0],
  ["v50 transformed children",lane.v72_transformed_children||lane.v50_transformed_children||0],
  ["v50 transform graphs",lane.v72_transform_graphs||lane.v50_transform_graphs||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 adds Cyber Sprint local coverage: PYC backdoor constants/CWE, recursive ZIP path phrases, pure-Python PCAP covert extraction and PNG alpha/RGB/hue streams. Web/OSINT can be skipped.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div>${sloper51BriefHtml(sum.sloper51_project_brief||sum.sloper50_project_brief||{})}<h3>Review Lanes</h3>${sloper51ReviewLanesHtml(sum.sloper51_review_lanes||sum.sloper50_review_lanes||{})}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check Project Brief, Priority Artifacts and Wrappers.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper51_next_actions||sum.sloper50_next_actions||sum.workflow_steps||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,36))}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,22).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloper52BriefHtml(b){
 b=b||{};
 const fam=b.artifact_families||{};
 const famRows=Object.keys(fam).sort().map(k=>`<span class=pill>${esc(k)}: ${esc(String(fam[k]))}</span>`).join(" ");
 return `<div class=find><h3>Project Brief</h3><div class=row><span class=score>${esc(b.status||"unknown")}</span><b>${esc(b.inspect_first||"Review artifacts")}</b></div><p class=sub>Promoted flags: ${esc(String(b.promoted_flags||0))} · Wrappers: ${esc(String(b.wrapper_candidates||0))} · Priority artifacts: ${esc(String(b.priority_artifacts||0))}</p><p class=sub>v72 generic coverage: ${esc(b.v72_generic_coverage||"not active")}</p><p>${famRows||'<span class=pill>no artifacts yet</span>'}</p>${b.warning?`<p class=warn>${esc(b.warning)}</p>`:""}</div>`
}
function sloper52ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Status",lane.status||"unknown"],
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrapper candidates",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["v72 magic carves",lane.v72_magic_carves||0],
  ["v72 ZIP passwords",lane.v72_zip_passwords||0],
  ["v72 binary constants",lane.v72_binary_constants||0],
  ["v72 entropy reports",lane.v72_entropy||0],
  ["v72 pure PCAP",lane.v72_pure_pcap||lane.v72_pure_pcap||0],
  ["v50 transformed children",lane.v72_transformed_children||lane.v50_transformed_children||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function sloper52CoverageHtml(rows){
 rows=rows||[];
 if(!rows.length) return '<p class=warn>No coverage matrix yet.</p>';
 return `<table><thead><tr><th>File</th><th>Flags</th><th>Artifacts</th><th>Inspect first</th></tr></thead><tbody>${rows.slice(0,24).map(r=>`<tr><td>${esc(r.file||"")}</td><td>${esc(String(r.flags||0))}</td><td>${esc(String(r.artifacts||0))}</td><td>${esc(r.recommended_first||"")}</td></tr>`).join("")}</tbody></table>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 adds generic CTF coverage: magic carving, clue-wordlist ZIP password attempts, binary constant-array decoding, entropy triage and a coverage matrix.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div>${sloper52BriefHtml(sum.sloper52_project_brief||sum.sloper51_project_brief||{})}<h3>Review Lanes</h3>${sloper52ReviewLanesHtml(sum.sloper52_review_lanes||sum.sloper51_review_lanes||{})}<h3>Coverage Matrix</h3>${sloper52CoverageHtml(sum.sloper52_coverage_matrix||[])}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check Coverage Matrix, Priority Artifacts and Wrappers.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper52_next_actions||sum.sloper51_next_actions||sum.workflow_steps||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,40))}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,24).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloper53BriefHtml(b){
 b=b||{};
 const fam=b.artifact_families||{};
 const famRows=Object.keys(fam).sort().map(k=>`<span class=pill>${esc(k)}: ${esc(String(fam[k]))}</span>`).join(" ");
 return `<div class=find><h3>Project Brief</h3><div class=row><span class=score>${esc(b.status||"unknown")}</span><b>${esc(b.inspect_first||"Review artifacts")}</b></div><p class=sub>Promoted flags: ${esc(String(b.promoted_flags||0))} · Wrappers: ${esc(String(b.wrapper_candidates||0))} · Priority artifacts: ${esc(String(b.priority_artifacts||0))}</p><p class=sub>v72 universal coverage: ${esc(b.v72_universal_coverage||"not active")}</p><p>${famRows||'<span class=pill>no artifacts yet</span>'}</p>${b.warning?`<p class=warn>${esc(b.warning)}</p>`:""}</div>`
}
function sloper53ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrapper candidates",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["v72 ZIP passwords",lane.v72_zip_passwords||0],
  ["v72 audio",lane.v72_audio||0],
  ["v72 SQLite",lane.v72_sqlite||0],
  ["v72 documents",lane.v72_documents||0],
  ["v72 source deobf",lane.v72_source_deobf||0],
  ["v72 magic carves",lane.v72_magic_carves||lane.v72_magic_carves||0],
  ["v72 pure PCAP",lane.v72_pure_pcap||lane.v72_pure_pcap||0],
  ["v50 transformed children",lane.v72_transformed_children||lane.v50_transformed_children||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function sloper53CoverageMatrixHtml(m){
 m=m||{};
 const rows=Object.keys(m).sort().map(k=>`<tr><td>${esc(k)}</td><td>${esc(String(m[k]))}</td></tr>`).join("");
 return `<table><thead><tr><th>Workflow family</th><th>Hits</th></tr></thead><tbody>${rows||'<tr><td>none</td><td>0</td></tr>'}</tbody></table>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 broadens universal CTF coverage: ZIP clue-passwords, WAV/audio LSB, SQLite/database dumps, Office/PDF raw text and source-code deobfuscation. Promoted flags stay strict; artifacts carry evidence.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div>${sloper53BriefHtml(sum.sloper53_project_brief||sum.sloper52_project_brief||sum.sloper51_project_brief||{})}<h3>Review Lanes</h3>${sloper53ReviewLanesHtml(sum.sloper53_review_lanes||sum.sloper52_review_lanes||sum.sloper51_review_lanes||{})}<h3>Coverage Matrix</h3>${sloper53CoverageMatrixHtml(sum.sloper53_coverage_matrix||{})}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check Project Brief, Coverage Matrix, Priority Artifacts and Wrappers.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper53_next_actions||sum.sloper52_next_actions||sum.workflow_steps||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,40))}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,24).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloper54BriefHtml(b){
 b=b||{};
 const fam=b.artifact_families||{};
 const famRows=Object.keys(fam).sort().map(k=>`<span class=pill>${esc(k)}: ${esc(String(fam[k]))}</span>`).join(" ");
 return `<div class=find><h3>Project Brief</h3><div class=row><span class=score>${esc(b.status||"unknown")}</span><b>${esc(b.inspect_first||"Review artifacts")}</b></div><p class=sub>Promoted flags: ${esc(String(b.promoted_flags||0))} · Wrappers: ${esc(String(b.wrapper_candidates||0))} · Priority artifacts: ${esc(String(b.priority_artifacts||0))}</p><p class=sub>v72 deep carve: ${esc(b.v72_deep_carve||"not active")}</p><p>${famRows||'<span class=pill>no artifacts yet</span>'}</p>${b.warning?`<p class=warn>${esc(b.warning)}</p>`:""}</div>`
}
function sloper54ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrapper candidates",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["v72 magic carves",lane.v72_magic_carves||0],
  ["v72 constant arrays",lane.v72_constant_arrays||0],
  ["v72 entropy maps",lane.v72_entropy_maps||0],
  ["v72 ZIP passwords",lane.v72_zip_passwords||lane.v72_zip_passwords||0],
  ["v72 audio",lane.v72_audio||lane.v72_audio||0],
  ["v72 SQLite",lane.v72_sqlite||lane.v72_sqlite||0],
  ["v51 pure PCAP",lane.v72_pure_pcap||lane.v51_pure_pcap||0],
  ["v50 transformed children",lane.v72_transformed_children||lane.v50_transformed_children||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function sloper54CoverageMatrixHtml(m){
 m=m||{};
 const rows=Object.keys(m).sort().map(k=>`<tr><td>${esc(k)}</td><td>${esc(String(m[k]))}</td></tr>`).join("");
 return `<table><thead><tr><th>Workflow family</th><th>Hits</th></tr></thead><tbody>${rows||'<tr><td>none</td><td>0</td></tr>'}</tbody></table>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 adds universal deep carving: embedded magic child extraction, byte/int constant-array solving and entropy offset maps. Carved children are saved and lightly analyzed.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div>${sloper54BriefHtml(sum.sloper54_project_brief||sum.sloper53_project_brief||{})}<h3>Review Lanes</h3>${sloper54ReviewLanesHtml(sum.sloper54_review_lanes||sum.sloper53_review_lanes||{})}<h3>Coverage Matrix</h3>${sloper54CoverageMatrixHtml(sum.sloper54_coverage_matrix||sum.sloper53_coverage_matrix||{})}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check magic_carve_manifest, constant_array candidates, Priority Artifacts and Wrappers.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper54_next_actions||sum.sloper53_next_actions||sum.workflow_steps||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,44))}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,24).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloper55BriefHtml(b){
 b=b||{};
 const fam=b.artifact_families||{};
 const famRows=Object.keys(fam).sort().map(k=>`<span class=pill>${esc(k)}: ${esc(String(fam[k]))}</span>`).join(" ");
 return `<div class=find><h3>Project Brief</h3><div class=row><span class=score>${esc(b.status||"unknown")}</span><b>${esc(b.inspect_first||"Review artifacts")}</b></div><p class=sub>Promoted flags: ${esc(String(b.promoted_flags||0))} · Wrappers: ${esc(String(b.wrapper_candidates||0))} · Priority artifacts: ${esc(String(b.priority_artifacts||0))}</p><p class=sub>v72 decode pipeline: ${esc(b.v72_decode_pipeline||"not active")}</p><p>${famRows||'<span class=pill>no artifacts yet</span>'}</p>${b.warning?`<p class=warn>${esc(b.warning)}</p>`:""}</div>`
}
function sloper55ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrapper candidates",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["v72 decode graphs",lane.v72_decode_graphs||0],
  ["v72 generic XOR",lane.v72_generic_xor||0],
  ["v72 magic carves",lane.v72_magic_carves||lane.v72_magic_carves||0],
  ["v72 constant arrays",lane.v72_constant_arrays||lane.v72_constant_arrays||0],
  ["v72 entropy maps",lane.v72_entropy_maps||lane.v72_entropy_maps||0],
  ["v53 ZIP passwords",lane.v72_zip_passwords||lane.v53_zip_passwords||0],
  ["v51 pure PCAP",lane.v72_pure_pcap||lane.v51_pure_pcap||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function sloper55CoverageMatrixHtml(m){
 m=m||{};
 const rows=Object.keys(m).sort().map(k=>`<tr><td>${esc(k)}</td><td>${esc(String(m[k]))}</td></tr>`).join("");
 return `<table><thead><tr><th>Workflow family</th><th>Hits</th></tr></thead><tbody>${rows||'<tr><td>none</td><td>0</td></tr>'}</tbody></table>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 adds recursive decode graph and generic XOR decoding across common CTF encodings/compressions. Use decode_graph.json first when present.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div>${sloper55BriefHtml(sum.sloper55_project_brief||sum.sloper54_project_brief||{})}<h3>Review Lanes</h3>${sloper55ReviewLanesHtml(sum.sloper55_review_lanes||sum.sloper54_review_lanes||{})}<h3>Coverage Matrix</h3>${sloper55CoverageMatrixHtml(sum.sloper55_coverage_matrix||sum.sloper54_coverage_matrix||{})}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check decode_graph, generic_xor, Priority Artifacts and Wrappers.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper55_next_actions||sum.sloper54_next_actions||sum.workflow_steps||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,46))}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,24).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloper56BriefHtml(b){
 b=b||{};
 const fam=b.artifact_families||{};
 const famRows=Object.keys(fam).sort().map(k=>`<span class=pill>${esc(k)}: ${esc(String(fam[k]))}</span>`).join(" ");
 return `<div class=find><h3>Project Brief</h3><div class=row><span class=score>${esc(b.status||"unknown")}</span><b>${esc(b.inspect_first||"Review artifacts")}</b></div><p class=sub>Promoted flags: ${esc(String(b.promoted_flags||0))} · Wrappers: ${esc(String(b.wrapper_candidates||0))} · Priority artifacts: ${esc(String(b.priority_artifacts||0))}</p><p class=sub>v72 multi-file pipeline: ${esc(b.v72_multifile_pipeline||"not active")}</p><p>${famRows||'<span class=pill>no artifacts yet</span>'}</p>${b.warning?`<p class=warn>${esc(b.warning)}</p>`:""}</div>`
}
function sloper56ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrapper candidates",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["v72 project multifile",lane.v72_project_multifile||0],
  ["v72 crib XOR",lane.v72_crib_xor||0],
  ["v72 JWT",lane.v72_jwt||0],
  ["v72 bitplanes",lane.v72_bitplanes||0],
  ["v72 decode graphs",lane.v72_decode_graphs||lane.v72_decode_graphs||0],
  ["v72 generic XOR",lane.v72_generic_xor||lane.v72_generic_xor||0],
  ["v54 magic carves",lane.v72_magic_carves||lane.v54_magic_carves||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function sloper56CoverageMatrixHtml(m){
 m=m||{};
 const rows=Object.keys(m).sort().map(k=>`<tr><td>${esc(k)}</td><td>${esc(String(m[k]))}</td></tr>`).join("");
 return `<table><thead><tr><th>Workflow family</th><th>Hits</th></tr></thead><tbody>${rows||'<tr><td>none</td><td>0</td></tr>'}</tbody></table>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 adds project-level multi-file XOR/ADD/SUB, known-plaintext XOR crib recovery, JWT decoding, and image bitplane contact sheets.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div>${sloper56BriefHtml(sum.sloper56_project_brief||sum.sloper55_project_brief||{})}<h3>Review Lanes</h3>${sloper56ReviewLanesHtml(sum.sloper56_review_lanes||sum.sloper55_review_lanes||{})}<h3>Coverage Matrix</h3>${sloper56CoverageMatrixHtml(sum.sloper56_coverage_matrix||sum.sloper55_coverage_matrix||{})}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check project_multifile, crib_xor, decode_graph, Priority Artifacts and Wrappers.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper56_next_actions||sum.sloper55_next_actions||sum.workflow_steps||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,50))}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,26).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI additions ==================== */
function sloper57BriefHtml(b){
 b=b||{};
 const fam=b.artifact_families||{};
 const famRows=Object.keys(fam).sort().map(k=>`<span class=pill>${esc(k)}: ${esc(String(fam[k]))}</span>`).join(" ");
 return `<div class=find><h3>Project Brief</h3><div class=row><span class=score>${esc(b.status||"unknown")}</span><b>${esc(b.inspect_first||"Review artifacts")}</b></div><p class=sub>Promoted flags: ${esc(String(b.promoted_flags||0))} · Wrappers: ${esc(String(b.wrapper_candidates||0))} · Priority artifacts: ${esc(String(b.priority_artifacts||0))}</p><p class=sub>v72 reasoning pipeline: ${esc(b.v72_reasoning_pipeline||"not active")}</p><p>${famRows||'<span class=pill>no artifacts yet</span>'}</p>${b.warning?`<p class=warn>${esc(b.warning)}</p>`:""}</div>`
}
function sloper57ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrapper candidates",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["v72 classic crypto",lane.v72_classic_crypto||0],
  ["v72 playbooks",lane.v72_playbooks||0],
  ["v56 project multifile",lane.v72_project_multifile||lane.v56_project_multifile||0],
  ["v56 crib XOR",lane.v72_crib_xor||lane.v56_crib_xor||0],
  ["v55 decode graphs",lane.v72_decode_graphs||lane.v55_decode_graphs||0],
  ["v54 magic carves",lane.v72_magic_carves||lane.v54_magic_carves||0],
  ["v54 constant arrays",lane.v72_constant_arrays||lane.v54_constant_arrays||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function sloper57CoverageMatrixHtml(m){
 m=m||{};
 const rows=Object.keys(m).sort().map(k=>`<tr><td>${esc(k)}</td><td>${esc(String(m[k]))}</td></tr>`).join("");
 return `<table><thead><tr><th>Workflow family</th><th>Hits</th></tr></thead><tbody>${rows||'<tr><td>none</td><td>0</td></tr>'}</tbody></table>`
}
function uxForgeDashboard(meta,sum){
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER AutoSolve</h3><p class=sub>v72 adds classical crypto and solver playbooks: Caesar, Atbash, ROT47, Morse, Bacon, Rail fence and Vigenere using clue-derived keys.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button></div>${sloper57BriefHtml(sum.sloper57_project_brief||sum.sloper56_project_brief||{})}<h3>Review Lanes</h3>${sloper57ReviewLanesHtml(sum.sloper57_review_lanes||sum.sloper56_review_lanes||{})}<h3>Coverage Matrix</h3>${sloper57CoverageMatrixHtml(sum.sloper57_coverage_matrix||sum.sloper56_coverage_matrix||{})}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check classic_crypto_candidates, decode_graph, multifile, Priority Artifacts and Wrappers.</p>'}<h3>Next Actions</h3>${sloperNextActionsHtml(sum.sloper57_next_actions||sum.sloper56_next_actions||sum.workflow_steps||[])}<h3>Priority Artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,50))}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,26).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}<h3>Evidence Timeline</h3>${sloperEvidenceTimelineHtml(sum.sloper43_evidence_timeline||[])}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI additions ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps compact UI ==================== */
function sloper72HubHtml(h){
 h=h||{}; const counts=h.counts||{};
 const pills=Object.keys(counts).sort().map(k=>`<span class=pill>${esc(k)}: ${esc(String(counts[k]))}</span>`).join(" ");
 const groups=h.groups||{};
 const start=(groups.start_here||[]).slice(0,16);
 return `<div class=find><h3>Artifact Hub</h3><p class=sub>Compact navigation for transformations and evidence. Use Start Here first, then open grouped artifacts only if needed.</p><p>${pills||'<span class=pill>no artifacts</span>'}</p>${artifactsHtml(start)}</div>`
}
function sloper72ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrappers",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["v72 zero-width",lane.v72_zero_width||0],
  ["v72 whitespace",lane.v72_whitespace_bits||0],
  ["v72 crashes",lane.v72_agent_crashes||0],
  ["v57 classic crypto",lane.v72_classic_crypto||lane.v57_classic_crypto||0],
  ["v56 multifile",lane.v72_project_multifile||lane.v56_project_multifile||0],
  ["v55 decode graph",lane.v72_decode_graphs||lane.v55_decode_graphs||0],
  ["v54 magic carves",lane.v72_magic_carves||lane.v54_magic_carves||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function uxForgeDashboard(meta,sum){
 const lane=sum.sloper72_review_lanes||sum.sloper57_review_lanes||sum.sloper56_review_lanes||{};
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER v77 Strict Wraps</h3><p class=sub>Modular entrypoint, lazy PIL/numpy, agent health, zero-width/whitespace artifacts, and compact artifact hub.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button> <button type=button class=btn onclick="window.open('/api/agent_health','_blank')">Agent Health</button></div><h3>Review Lanes</h3>${sloper72ReviewLanesHtml(lane)}${sloper72HubHtml(sum.sloper72_artifact_hub||{})}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag)} <button type=button class=btn onclick="copyText('${escAttr(x.flag)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check Artifact Hub and Wrappers.</p>'}<h3>Action Queue</h3>${sloperNextActionsHtml(sum.sloper72_next_actions||sum.sloper57_next_actions||sum.workflow_steps||[])}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,20).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps compact UI ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI ==================== */
function sloper74ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrappers",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["v74 workflows",lane.v74_workflow_artifacts||0],
  ["v74 multifile",lane.v74_project_multifile||lane.project_multifile||0],
  ["v72 zero-width",lane.v72_zero_width||0],
  ["v72 whitespace",lane.v72_whitespace_bits||0],
  ["Agent crashes",lane.v72_agent_crashes||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function uxForgeDashboard(meta,sum){
 const lane=sum.sloper74_review_lanes||sum.sloper72_review_lanes||{};
 const hub=sum.sloper74_artifact_hub||sum.sloper72_artifact_hub||{};
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER v77 Strict Wraps</h3><p class=sub>Evidence-first workflow solving: decode graph, XOR, arrays, archives, carving, image stego, PCAP, WAV, SQLite, PDF, JWT, logs and project multifile. Final flags require strict ctf_cs evidence.</p><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button> <button type=button class=btn onclick="window.open('/api/agent_health','_blank')">Agent Health</button></div><h3>Review Lanes</h3>${sloper74ReviewLanesHtml(lane)}${sloper72HubHtml(hub)}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag||x)} <button type=button class=btn onclick="copyText('${escAttr(x.flag||x)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check Artifact Hub and workflow evidence.</p>'}<h3>Workflow Evidence</h3>${(sum.workflow_evidence||[]).slice(0,30).map(e=>`<div class=find><b>${esc(e.flag||'')}</b><p class=sub>${esc(e.why||'')} — ${esc(e.source||'')}</p>${e.artifact?`<a class=btn href="/api/raw?path=${encodeURIComponent(e.artifact)}" target=_blank>open evidence</a>`:''}</div>`).join("")||'<p class=warn>No workflow evidence yet.</p>'}<h3>Action Queue</h3>${sloperNextActionsHtml(sum.sloper72_next_actions||sum.workflow_steps||[])}<h3>Wrappers</h3>${(sum.flag_wrapping_helpers||[]).slice(0,20).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI ==================== */


/* ==================== CTF SLOPER v77 Strict Wraps UI ==================== */
let sl75RunStartedAt = null;
let sl75TimerHandle = null;
function sl75StartTimer(){
 sl75RunStartedAt = Date.now();
 const el=document.getElementById('sl75Timer');
 if(sl75TimerHandle) clearInterval(sl75TimerHandle);
 sl75TimerHandle=setInterval(()=>{ if(el&&sl75RunStartedAt){ el.textContent=((Date.now()-sl75RunStartedAt)/1000).toFixed(1)+'s'; } },250);
}
async function sl75Cancel(pid){
 try{
  await fetch('/api/v75/cancel/'+encodeURIComponent(pid), {method:'POST'});
  alert('Cancel requested for project '+pid+'. If a legacy subprocess/tool is already running, it may stop after current step.');
 }catch(e){ alert('Cancel request failed: '+e); }
}
const _sl75OldRunAggressive = window.runAggressiveAgents;
window.runAggressiveAgents = async function(pid){
 sl75StartTimer();
 const old = _sl75OldRunAggressive;
 try{
  return await old(pid);
 } finally {
  if(sl75TimerHandle) clearInterval(sl75TimerHandle);
 }
}
function sloper75ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Wrappers",lane.wrapper_candidates_count||0],
  ["Priority artifacts",lane.priority_artifacts_count||0],
  ["v75 route",lane.v75_route_transposition||0],
  ["v75 artifacts",lane.v75_workflow_artifacts||0],
  ["v74 artifacts",lane.v74_workflow_artifacts||0],
  ["v74 multifile",lane.v74_project_multifile||lane.project_multifile||0],
  ["v72 hidden",lane.v72_zero_width||0],
  ["Agent crashes",lane.v72_agent_crashes||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function uxForgeDashboard(meta,sum){
 const lane=sum.sloper75_review_lanes||sum.sloper74_review_lanes||sum.sloper72_review_lanes||{};
 const hub=sum.sloper75_artifact_hub||sum.sloper74_artifact_hub||sum.sloper72_artifact_hub||{};
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER v77 Strict Wraps</h3><p class=sub>Routed evidence-first solving. Agents are selected by file type and task hints. Route transposition added. Less random TXT hunting; final flags need strict ctf_cs evidence.</p><div class=row><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button><button type=button class=btn onclick="sl75Cancel('${meta.id}')">Stop project</button><button type=button class=btn onclick="window.open('/api/agent_health','_blank')">Agent Health</button><span class=pill>runtime: <b id=sl75Timer>0.0s</b></span></div></div><h3>Review Lanes</h3>${sloper75ReviewLanesHtml(lane)}${sloper72HubHtml(hub)}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag||x)} <button type=button class=btn onclick="copyText('${escAttr(x.flag||x)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check Artifact Hub and workflow evidence.</p>'}<h3>Workflow Evidence</h3>${(sum.workflow_evidence||[]).slice(0,35).map(e=>`<div class=find><b>${esc(e.flag||'')}</b><p class=sub>${esc(e.why||'')} — ${esc(e.source||'')}</p>${e.artifact?`<a class=btn href="/api/raw?path=${encodeURIComponent(e.artifact)}" target=_blank>open evidence</a>`:''}</div>`).join("")||'<p class=warn>No workflow evidence yet.</p>'}<h3>Action Queue</h3>${sloperNextActionsHtml(sum.sloper75_next_actions||sum.sloper72_next_actions||sum.workflow_steps||[])}<h3>Wrappers / Candidates</h3>${(sum.flag_wrapping_helpers||sum.candidate_flags||[]).slice(0,20).map(w=>`<div class=find><div class=row><span class=score>${w.score||0}</span><b>${esc(w.suggested_flag||w.candidate||"")}</b></div><p class=sub>${esc(w.why||"")} — ${esc(w.source||"")}</p><button type=button class=btn onclick="copyText('${escAttr(w.suggested_flag||w.candidate||"")}')">copy</button></div>`).join("")||'<p class=warn>No wrapper candidates.</p>'}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI ==================== */


/* v75 auto project title from first file */
document.addEventListener('change', function(e){
 const t=e.target;
 if(!t || t.type!=='file' || !t.files || !t.files.length) return;
 const title=document.querySelector('input[name="title"], #title, input[placeholder*="title" i], input[placeholder*="pavad" i]');
 if(title && !title.value.trim()){
   title.value=t.files[0].name.replace(/\.[^.]+$/,'');
 }
}, true);


/* ==================== CTF SLOPER v77 Strict Wraps UI ==================== */
function sloper76SemanticCandidatesHtml(cands){
 cands=cands||[];
 if(!cands.length) return '<p class=warn>No semantic answer candidates yet.</p>';
 return cands.slice(0,30).map(c=>`<div class=find><div class=row><span class=score>${esc(String(c.score||0))}</span><b>${esc(c.candidate||c.suggested_flag||'')}</b><span class=pill>${esc(c.priority||'candidate')}</span></div><p class=sub>${esc(c.why||'')} — ${esc(c.source||'')}</p><p class=sub>normalized: ${esc(c.normalized||'')} · tokens: ${esc((c.tokens||[]).join(', '))}</p>${c.artifact?`<a class=btn href="/api/raw?path=${encodeURIComponent(c.artifact)}" target=_blank>open evidence</a>`:''} <button type=button class=btn onclick="copyText('${escAttr(c.candidate||c.suggested_flag||'')}')">copy</button></div>`).join('');
}
function sloper76ReviewLanesHtml(lane){
 lane=lane||{};
 const rows=[
  ["Promoted flags",lane.promoted_flags_count||0],
  ["Semantic candidates",lane.v76_semantic_candidates||0],
  ["Top candidates",lane.v76_top_candidates||0],
  ["v75 route",lane.v75_route_transposition||0],
  ["v75 artifacts",lane.v75_workflow_artifacts||0],
  ["v74 artifacts",lane.v74_workflow_artifacts||0],
  ["v74 multifile",lane.v74_project_multifile||lane.project_multifile||0],
  ["Agent crashes",lane.v72_agent_crashes||0]
 ];
 return `<div class=grid3>${rows.map(r=>`<div class=metric><b>${esc(String(r[1]))}</b><div class=sub>${esc(r[0])}</div></div>`).join("")}</div>`
}
function uxForgeDashboard(meta,sum){
 const lane=sum.sloper76_review_lanes||sum.sloper75_review_lanes||sum.sloper74_review_lanes||{};
 const hub=sum.sloper76_artifact_hub||sum.sloper75_artifact_hub||sum.sloper74_artifact_hub||sum.sloper72_artifact_hub||{};
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER v77 Strict Wraps</h3><p class=sub>Evidence-first + semantic answer ranking. Full ctf_cs flags are promoted. Clean LT/EN/leetspeak {body} outputs from transforms become top answer candidates, not random guesses.</p><div class=row><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button><button type=button class=btn onclick="sl75Cancel('${meta.id}')">Stop project</button><button type=button class=btn onclick="window.open('/api/agent_health','_blank')">Agent Health</button><span class=pill>runtime: <b id=sl75Timer>0.0s</b></span></div></div><h3>Review Lanes</h3>${sloper76ReviewLanesHtml(lane)}<h3>Semantic Answer Candidates</h3>${sloper76SemanticCandidatesHtml(sum.semantic_answer_candidates||[])}${sloper72HubHtml(hub)}<h3>Promoted ctf_cs flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag||x)} <button type=button class=btn onclick="copyText('${escAttr(x.flag||x)}')">copy</button><span class=sub> ${esc(x.file||"")}</span></div>`).join("")||'<p class=warn>No strict promoted flag yet. Check Semantic Candidates and Artifact Hub.</p>'}<h3>Workflow Evidence</h3>${(sum.workflow_evidence||[]).slice(0,35).map(e=>`<div class=find><b>${esc(e.flag||'')}</b><p class=sub>${esc(e.why||'')} — ${esc(e.source||'')}</p>${e.artifact?`<a class=btn href="/api/raw?path=${encodeURIComponent(e.artifact)}" target=_blank>open evidence</a>`:''}</div>`).join("")||'<p class=warn>No workflow evidence yet.</p>'}<h3>Action Queue</h3>${sloperNextActionsHtml(sum.sloper76_next_actions||sum.sloper75_next_actions||sum.sloper72_next_actions||sum.workflow_steps||[])}`
}
/* ==================== end CTF SLOPER v77 Strict Wraps UI ==================== */


/* ==================== CTF SLOPER v77 simplified UI ==================== */
function sloper77WrapCandidatesHtml(cands){
 cands=cands||[];
 if(!cands.length) return '<p class=warn>No strict wrap candidates yet.</p>';
 return cands.slice(0,24).map(c=>`<div class=find><div class=row><span class=score>${esc(String(c.score||0))}</span><b>${esc(c.candidate||'')}</b><span class=pill>${esc(c.origin||'braced')}</span><span class=pill>${esc(c.priority||'candidate')}</span></div><p class=sub>${esc(c.why||'')} — ${esc(c.source||'')}</p><p class=sub>normalized: ${esc(c.normalized||'')} · tokens: ${esc((c.tokens||[]).join(', '))}</p>${c.artifact?`<a class=btn href="/api/raw?path=${encodeURIComponent(c.artifact)}" target=_blank>open evidence</a>`:''} <button type=button class=btn onclick="copyText('${escAttr(c.candidate||'')}')">copy</button></div>`).join('');
}
function sloper77EvidenceArtifactsHtml(arts){
 arts=(arts||[]).slice(0,32);
 if(!arts.length) return '<p class=warn>No evidence artifacts yet.</p>';
 return artifactsHtml(arts);
}
function uxForgeDashboard(meta,sum){
 const hub=sum.sloper77_artifact_hub||sum.sloper76_artifact_hub||sum.sloper75_artifact_hub||sum.sloper74_artifact_hub||sum.sloper72_artifact_hub||{};
 const start=(hub.groups&&hub.groups.start_here)||sum.artifacts||[];
 const lane=sum.sloper77_review_lanes||{};
 return `${sloperStatusPanel(sum)}<div class=find><h3>CTF SLOPER v77</h3><p class=sub>Strict evidence-first UI. Final flags are separate from wrap candidates. Wrap candidates normally require a braced {body} from a real transform artifact.</p><div class=row><button type=button class="btn primary" onclick="runAggressiveAgents('${meta.id}')">Run AutoSolve</button><button type=button class=btn onclick="sl75Cancel('${meta.id}')">Stop project</button><button type=button class=btn onclick="window.open('/api/agent_health','_blank')">Agent Health</button><span class=pill>runtime: <b id=sl75Timer>0.0s</b></span><span class=pill>wraps: ${esc(String(lane.v77_wrap_candidates||0))}</span></div></div><h3>Final Flags</h3>${(sum.flags||[]).map(x=>`<div class=flag>${esc(x.flag||x)} <button type=button class=btn onclick="copyText('${escAttr(x.flag||x)}')">copy</button><span class=sub> ${esc(x.file||'')}</span></div>`).join('')||'<p class=warn>No strict ctf_cs final flag yet.</p>'}<h3>Wrap Candidates</h3>${sloper77WrapCandidatesHtml(sum.wrap_candidates||sum.semantic_answer_candidates||[])}<h3>Evidence Artifacts</h3>${sloper77EvidenceArtifactsHtml(start)}<h3>Workflow Evidence</h3>${(sum.workflow_evidence||[]).slice(0,25).map(e=>`<div class=find><b>${esc(e.flag||'')}</b><p class=sub>${esc(e.why||'')} — ${esc(e.source||'')}</p>${e.artifact?`<a class=btn href="/api/raw?path=${encodeURIComponent(e.artifact)}" target=_blank>open evidence</a>`:''}</div>`).join('')||'<p class=warn>No workflow evidence yet.</p>'}`
}
/* ==================== end CTF SLOPER v77 simplified UI ==================== */

/* ==================== CTF SLOPER v88 focused workspace override ==================== */
function artifactsHtml(items){
 if(!items||!items.length)return '<p class=warn>No artifacts yet. Run analysis or AutoSolve.</p>';
 const f=String(window.artifactFilter||'').toLowerCase();
 const shown=items.filter(a=>!f || (`${a.kind} ${a.name} ${a.file} ${a.source_file} ${a.source} ${a.method} ${a.note} ${a.priority_reason}`.toLowerCase().includes(f))).slice(0,700);
 return `<div class=visualToolbar><input class=search placeholder="Filter artifacts by kind, filename, source, note..." oninput="artifactFilter=this.value;renderProject()" value="${escAttr(window.artifactFilter||'')}"><span class=pill>${shown.length}/${items.length}</span></div><div class=artifactGrid>${shown.map(a=>{const raw=a.url||('/api/raw?path='+encodeURIComponent(a.path||''));const preview=String(a.preview||a.preview_text||'').slice(0,900);const pri=a.open_first||a.human_priority;return `<div class="artifactCard ${pri?'v98-running':''}"><div class=row><span class=score>${a.human_priority||a.score||0}</span>${pri?'<span class="pill ok">OPEN FIRST</span>':''}<span class=pill>${esc(a.kind||"artifact")}</span><span class=pill>${esc(a.file||a.source_file||"")}</span></div><h4>${artifactIcon(a.kind)} ${esc(a.name||"")}</h4><div class=sub>${esc(a.source||a.method||"")} - ${esc(a.size||0)} bytes - ${a.exists===false?'missing':'exists'}</div>${a.priority_reason?`<p class=ok>${esc(a.priority_reason)}</p>`:''}<p>${esc(a.note||"")}</p>${preview?`<details open><summary>preview</summary><pre>${esc(preview)}</pre></details>`:''}<div class=actions><button type=button class=btn onclick="copyText('${escAttr(a.path||"")}')">copy path</button><a class=btn target=_blank href="${raw}">open</a><a class=btn target=_blank download href="${raw}">download</a></div></div>`}).join("")}</div>`
}
function sloper88FlagValue(x){return (typeof x==='string')?x:(x&&x.flag)||''}
function sloper88Runtime(job){
 job=job||{};
 const e=Number(job.elapsed||0);
 if(e>0)return e.toFixed(1)+'s';
 if(job.started)return ((Date.now()/1000)-Number(job.started)).toFixed(1)+'s';
 return job.status==='running'?'running':'idle';
}
function sloper100PriorityArtifacts(sum){
 const items=sum.priority_artifacts||sum.human_review_artifacts||[];
 if(!items.length)return '<p class=warn>No Open First artifacts yet. Run AutoSolve or inspect Artifact Hub.</p>';
 return `<div class=find><h3>Open First</h3><p class=sub>These are the artifacts most likely to need human eyes: visual reconstructions, transform hits, leetspeak/alternate-format sources, and direct workflow evidence.</p>${artifactsHtml(items.slice(0,48))}</div>`;
}
function sloper102PreflightPanel(sum){
 const pf=sum.sloper102_preflight||{};
 const hits=pf.hits||[];
 const steps=pf.steps||[];
 const routes=sum.sloper102_routes||[];
 if(!hits.length&&!steps.length&&!routes.length)return '';
 return `<div class=find><h3>Logical Preflight</h3><p class=sub>${esc(pf.note||'Fast CTF reasoning ran before broad legacy sweeps.')}</p>${routes.length?`<div class=row>${routes.map(r=>`<span class=pill>${esc(r.mode||'route')}: ${esc(r.why||'')}</span>`).join('')}</div>`:''}<h4>Best transform hits</h4>${hits.slice(0,20).map(h=>`<div class=find><div class=row><span class=score>${h.score||0}</span><b>${esc(h.method||'transform')}</b>${h.artifact?`<a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(h.artifact)}">open</a><button type=button class=btn onclick="copyText('${escAttr(h.artifact)}')">copy path</button>`:''}</div><p class=sub>${esc(h.why||'')}</p>${h.preview?`<pre>${esc(String(h.preview).slice(0,700))}</pre>`:''}</div>`).join('')||'<p class=warn>No high-confidence preflight hit yet.</p>'}<details open><summary>reasoning steps</summary>${steps.slice(0,50).map(s=>`<div class=row><span class=pill>${s.hit?'hit':'checked'}</span><span>${esc(s.step||'')}</span><span class=sub>${esc(s.why||'')}</span></div>`).join('')}</details></div>`;
}
function sloper88Actions(meta,sum){
 const actions=[...(sum.sloper93_next_actions||[]),...(sum.sloper77_next_actions||[]),...(sum.sloper76_next_actions||[]),...(sum.sloper75_next_actions||[]),...(sum.sloper74_next_actions||[]),...(sum.workflow_steps||[])];
 return `${sloper102PreflightPanel(sum)}${sloper100PriorityArtifacts(sum)}<h3>Action Queue</h3>${sloperNextActionsHtml(actions.slice(0,24))}<h3>Workflow Evidence</h3>${(sum.workflow_evidence||[]).slice(0,30).map(e=>`<div class=find><b>${esc(e.flag||'')}</b><p class=sub>${esc(e.why||'')} - ${esc(e.source||'')}</p>${e.artifact?`<a class=btn href="/api/raw?path=${encodeURIComponent(e.artifact)}" target=_blank>open evidence</a> <button type=button class=btn onclick="copyText('${escAttr(e.artifact)}')">copy path</button>`:''}</div>`).join('')||'<p class=warn>No evidence yet.</p>'}`;
}
function sloper88Flags(sum){
 const flags=(sum.flags||[]).map(sloper88FlagValue).filter(Boolean);
 const unconfirmed=[...(sum.unconfirmed_evidence||[]),...(sum.answer_candidates||[]),...(sum.alternate_flag_candidates||[])];
 const seen=new Set();
 const rows=unconfirmed.filter(x=>{const k=String((x&&x.value)||(x&&x.candidate)||(x&&x.flag)||(x&&x.body)||'')+'|'+String((x&&x.artifact)||''); if(!k.trim()||seen.has(k))return false; seen.add(k); return true;}).slice(0,240);
 return `<h3>Final Flags</h3>${flags.map(f=>`<div class=flag>${esc(f)} <button type=button class=btn onclick="copyText('${escAttr(f)}')">copy flag</button></div>`).join('')||'<p class=warn>No strict final flag yet.</p>'}<h3>Unconfirmed Evidence / Fragments</h3>${rows.map(x=>{const val=(x.value||x.candidate||x.flag||x.body||'');const wrap=x.wrapped_if_required||'';return `<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(val)}</b><button type=button class=btn onclick="copyText('${escAttr(val)}')">copy</button>${wrap?`<button type=button class=btn onclick="copyText('${escAttr(wrap)}')">copy ctf_cs</button>`:''}<span class=pill>${esc(x.bucket||'candidate')}</span><span class=pill>${esc(x.file||x.source_file||'')}</span></div><p class=sub>${esc(x.why||x.why_not_promoted||'Preserved for human review.')}</p>${x.artifact?`<a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.artifact)}">open evidence</a> <button type=button class=btn onclick="copyText('${escAttr(x.artifact)}')">copy path</button>`:''}</div>`}).join('')||'<p class=warn>No unconfirmed candidates yet.</p>'}<h3>Wrapper Candidates</h3>${sloper77WrapCandidatesHtml(sum.wrap_candidates||sum.semantic_answer_candidates||sum.candidate_flags||[])}`;
}
function sloper88Artifacts(sum){
 const hub=sum.sloper93_artifact_hub||sum.sloper77_artifact_hub||sum.sloper76_artifact_hub||sum.sloper75_artifact_hub||sum.sloper74_artifact_hub||sum.sloper72_artifact_hub||{};
 return `${sloper100PriorityArtifacts(sum)}${sloper72HubHtml(hub)}<h3>High-value artifacts</h3>${artifactsHtml((sum.artifacts||[]).slice(0,240))}`;
}
function sloper88Health(job,sum){
 const health=sum.health||{};
 const crashes=(sum.sloper93_agent_health||sum.agent_health||sum.sloper72_agent_health||[]).slice(-40);
 return `<h3>Runtime</h3><div class=grid3><div class=metric><b>${esc(job.status||'idle')}</b><div class=sub>status</div></div><div class=metric><b>${esc(String(job.progress||0))}%</b><div class=sub>progress</div></div><div class=metric><b>${esc(sloper88Runtime(job))}</b><div class=sub>runtime</div></div><div class=metric><b>${esc(String((sum.artifacts||[]).length))}</b><div class=sub>artifacts</div></div><div class=metric><b>${esc(String((sum.workflow_evidence||[]).length))}</b><div class=sub>evidence</div></div><div class=metric><b>${esc(String(crashes.length))}</b><div class=sub>agent health</div></div></div>${healthHtml(health)}<h3>Slow / failed agents</h3>${crashes.length?crashes.map(x=>`<div class=find><b>${esc(x.agent||x.name||'agent')}</b><p class=sub>${esc(x.error||x.message||'')}</p><pre>${esc((x.traceback||'').slice(0,1200))}</pre></div>`).join(''):'<p class=ok>No recent agent crashes.</p>'}`;
}
async function stopProject(pid){
 try{await fetch('/api/projects/'+encodeURIComponent(pid)+'/stop',{method:'POST'}); await openProject(pid,false); await loadProjects();}
 catch(e){alert('Stop failed: '+e);}
}
const _sloper88OldStartProject = window.startProject;
startProject=async function(id){await fetch(`/api/projects/${id}/start`,{method:'POST'}); sl75StartTimer(); startPolling(id); await openProject(id,false)}
loadProjects=async function(){
 const r=await fetch('/api/projects'); const j=await r.json();
 projectList.innerHTML=(j.projects||[]).map(p=>{const s=p.summary||{},flags=s.flags||[],arts=s.artifacts||[];return `<div class=project><div class=row><b>${esc(p.title)}</b><span class=pill>${esc(p.category||'auto')}</span><span class=pill>${esc(p.runtime_status||'')}</span><span class=pill>${p.progress||0}%</span><span class=pill>${flags.length} flags</span><span class=pill>${arts.length} artifacts</span></div><div class=progress><div class=bar style="width:${p.progress||0}%"></div></div><div class=sub>${esc(p.stage||'')}</div><button type=button class=btn onclick="openProject('${p.id}')">Open</button><button type=button class=btn onclick="startProject('${p.id}')">Run</button><button type=button class=btn onclick="stopProject('${p.id}')">Stop</button></div>`}).join('');
}
renderProject=function(){
 const j=currentData||{},rep=j.report||{},meta=j.project||{},job=j.job||{},files=rep.files||[],sum=rep.summary||{};
 if(selectedFile>=files.length)selectedFile=0;
 projectPrompt=rep.ai_prompt||'';
 const tabs=['Brief','Actions','Flags','Artifacts','Transforms','Files','Health','Logs'];
 const flags=(sum.flags||[]).map(sloper88FlagValue).filter(Boolean);
 const body=[
  uxForgeDashboard(meta,sum),
  sloper88Actions(meta,sum),
  sloper88Flags(sum),
  sloper88Artifacts(sum),
  artifactsHtml((sum.transformations||sum.artifacts||[]).filter(a=>String(a.kind||a.source||'').toLowerCase().match(/transform|decode|carve|extract|lsb|xor|route|zip|tar|gzip|local_header/)).slice(0,260)),
  filesWorkspace(files),
  sloper88Health(job,sum),
  `<pre>${esc(j.log||'')}</pre>`
 ];
 projectView.innerHTML=`<div class=card><div class=row between><h2>${esc(meta.title||'Project')}</h2><div class=row><button type=button class="btn primary" onclick="startProject('${meta.id}')">Run AutoSolve</button><button type=button class=btn onclick="stopProject('${meta.id}')">Stop project</button><span class=pill>runtime ${esc(sloper88Runtime(job))}</span></div></div><div class=grid3><div class=metric><b>${job.progress||0}%</b><div class=sub>progress</div></div><div class=metric><b>${files.length}</b><div class=sub>files</div></div><div class=metric><b>${flags.length}</b><div class=sub>final flags</div></div><div class=metric><b>${(sum.unconfirmed_evidence||[]).length+(sum.wrap_candidates||[]).length}</b><div class=sub>review candidates</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${(sum.workflow_evidence||[]).length}</b><div class=sub>evidence</div></div></div><div class=progress><div class=bar style="width:${job.progress||0}%"></div></div><div class=row><span class=pill>ID ${esc(meta.id||'')}</span><span class=pill>${esc(meta.category||'')}</span><span class=pill>${esc(job.stage||'')}</span></div></div><div class=card><div class=tabs>${tabs.map((t,i)=>`<button type=button class="${i===activeProjectTab?'on':''}" onclick="setProjectTab(${i})">${t}</button>`).join('')}</div>${body.map((h,i)=>`<div id=proj${i} class="${activeProjectTab===i?'':'hidden'}">${h}</div>`).join('')}</div>`;
}
filesWorkspace=function(files){
 files=files||[];
 const kinds=[...new Set(files.map(f=>f.kind||"generic"))];
 const shown=files.map((f,i)=>({...f,_idx:i})).filter(f=>(fileKindFilter==="all"||f.kind===fileKindFilter)&&(!fileSearch||(`${f.rel} ${f.name} ${f.kind}`.toLowerCase().includes(fileSearch.toLowerCase()))));
 return `<div class=row><input class=search placeholder="Search files..." value="${escAttr(fileSearch)}" oninput="fileSearch=this.value;renderProject()"><select onchange="fileKindFilter=this.value;renderProject()"><option value=all>all kinds</option>${kinds.map(k=>`<option value="${escAttr(k)}" ${fileKindFilter===k?'selected':''}>${esc(k)}</option>`).join("")}</select><span class=pill>${shown.length}/${files.length}</span></div><div class=grid2><div class=fileList>${shown.map(f=>`<div class="fileMini ${f._idx===selectedFile?'active':''}" onclick="selectFile(${f._idx})"><b>${esc(f.rel||f.name)}</b><div class=sub>${esc(f.kind||'generic')} - ${f.size||0} bytes - entropy ${f.entropy||"?"}</div><span class=pill>${(f.flags||[]).length} flags</span><span class=pill>${(f.answer_candidates||[]).length+(f.unconfirmed_evidence||[]).length} candidates</span><span class=pill>${(f.artifacts||[]).length} artifacts</span></div>`).join("")||'<p class=warn>No files match filter.</p>'}</div><div>${fileDetail(files[selectedFile]||shown[0])}</div></div>`;
}
fileDetail=function(f){
 if(!f)return"<p>No file selected.</p>";
 const raw=f.path?('/api/raw?path='+encodeURIComponent(f.path)):'#';
 const tabs=["Summary","Evidence","Artifacts","Transforms","Preview","Tools"];
 const evidence=[...(f.workflow_evidence||[]),...(f.answer_candidates||[]),...(f.unconfirmed_evidence||[]),...(f.alternate_flag_candidates||[])];
 const transforms=(f.transformations||f.artifacts||[]).filter(a=>String(a.kind||a.source||a.name||'').toLowerCase().match(/transform|decode|carve|extract|lsb|xor|route|zip|tar|gzip|local_header|preflight|columnar|rail|rot/));
 const body=[
  fileSummary(f),
  evidence.length?evidence.slice(0,120).map(x=>{const val=x.flag||x.value||x.candidate||x.body||'';return `<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(val)}</b><button type=button class=btn onclick="copyText('${escAttr(val)}')">copy</button>${x.wrapped_if_required?`<button type=button class=btn onclick="copyText('${escAttr(x.wrapped_if_required)}')">copy ctf_cs</button>`:''}</div><p class=sub>${esc(x.why||x.why_not_promoted||x.source||'')}</p>${x.artifact?`<a class=btn target=_blank href="/api/raw?path=${encodeURIComponent(x.artifact)}">open evidence</a>`:''}</div>`}).join(''):'<p class=warn>No file-level evidence yet.</p>',
  artifactsHtml(f.artifacts||[]),
  artifactsHtml(transforms),
  previewHtml(f),
  `${toolsHtml(f)}<h3>Useful raw access</h3><div class=row><a class=btn target=_blank href="${raw}">open raw file</a><a class=btn target=_blank download href="${raw}">download file</a><button type=button class=btn onclick="copyText('${escAttr(f.path||'')}')">copy local path</button></div><h3>Strings</h3><pre>${esc((f.strings||[]).join("\\n").slice(0,20000))}</pre>`
 ];
 if(activeFileTab>=tabs.length)activeFileTab=0;
 return `<div class=panel><div class=row between><h3>${esc(f.rel||f.name)}</h3><div class=row><a class=btn target=_blank href="${raw}">open</a><a class=btn target=_blank download href="${raw}">download</a><button type=button class=btn onclick="copyText('${escAttr(f.path||"")}')">copy path</button></div></div><div class=row><span class=pill>${esc(f.kind||'generic')}</span><span class=pill>${f.size||0} bytes</span><span class=pill>entropy ${f.entropy||"?"}</span><span class=pill>${(f.artifacts||[]).length} artifacts</span></div><div class=tabs>${tabs.map((t,k)=>`<button type=button class="${k===activeFileTab?'on':''}" onclick="setFileTab(${k})">${t}</button>`).join("")}</div>${body.map((h,i)=>`<div class="${i===activeFileTab?'':'hidden'}">${h}</div>`).join('')}</div>`;
}
/* ==================== end CTF SLOPER v88 focused workspace override ==================== */

/* ==================== CTF SLOPER FINAL focused operator UI ==================== */
function finalRaw(path){return path?('/api/raw?path='+encodeURIComponent(path)):'#'}
function finalVal(x){return (typeof x==='string')?x:(x&&x.flag)||(x&&x.value)||(x&&x.candidate)||(x&&x.body)||''}
function finalArtifactCards(items,limit=220){
 items=items||[];
 if(!items.length)return '<p class=warn>No artifacts in this group yet.</p>';
 const f=String(window.artifactFilter||'').toLowerCase();
 const shown=items.filter(a=>!f || (`${a.kind} ${a.name} ${a.file} ${a.source_file} ${a.source} ${a.method} ${a.note} ${a.priority_reason} ${a.path}`.toLowerCase().includes(f))).slice(0,limit);
 return `<div class=visualToolbar><input class=search placeholder="Search artifacts, source file, method, note..." oninput="artifactFilter=this.value;renderProject()" value="${escAttr(window.artifactFilter||'')}"><span class=pill>${shown.length}/${items.length}</span><label class=pill><input type=checkbox onchange="window.highOnly=this.checked;renderProject()" ${window.highOnly?'checked':''}> high confidence only</label></div><div class=artifactGrid>${shown.filter(a=>!window.highOnly || Number(a.human_priority||a.score||0)>=850).map(a=>{const raw=finalRaw(a.path||'');const preview=String(a.preview||a.preview_text||'').slice(0,1200);return `<div class="artifactCard ${a.open_first?'v98-running':''}"><div class=row><span class=score>${esc(String(a.human_priority||a.score||0))}</span>${a.open_first?'<span class="pill ok">OPEN FIRST</span>':''}<span class=pill>${esc(a.kind||'artifact')}</span><span class=pill>${esc(a.file||a.source_file||'project')}</span></div><h4>${artifactIcon(a.kind)} ${esc(a.name||'artifact')}</h4><p class=sub>${esc(a.source||a.method||'')} - ${esc(String(a.size||0))} bytes - ${a.exists===false?'missing':'exists'}</p>${a.priority_reason?`<p class=ok>${esc(a.priority_reason)}</p>`:''}<p>${esc(a.note||'')}</p>${preview?`<details open><summary>preview</summary><pre>${esc(preview)}</pre></details>`:''}<div class=actions><a class=btn target=_blank href="${raw}">open</a><a class=btn target=_blank download href="${raw}">download</a><button type=button class=btn onclick="copyText('${escAttr(a.path||'')}')">copy path</button></div></div>`}).join('')}</div>`;
}
function finalWorkflowMap(sum){
 const lanes=sum.final_workflow_map||{};
 const list=Object.keys(lanes).map(k=>({key:k,...lanes[k]})).sort((a,b)=>(b.priority||0)-(a.priority||0));
 if(!list.length)return '<p class=warn>No workflow lanes yet.</p>';
 return `<div class=grid3>${list.map(l=>`<div class=metric><b>${esc(String(l.count||0))}</b><div class=sub>${esc(l.title||l.key)}</div><p class=sub>${esc(l.why||'')}</p></div>`).join('')}</div>`;
}
function finalBrief(meta,sum,job,files){
 const flags=(sum.flags||[]).map(finalVal).filter(Boolean);
 const queue=sum.final_open_queue||sum.priority_artifacts||[];
 return `${sloper102PreflightPanel(sum)}<h3>Project Brief</h3><div class=grid3><div class=metric><b>${esc(job.status||'idle')}</b><div class=sub>status</div></div><div class=metric><b>${esc(sloper88Runtime(job))}</b><div class=sub>runtime</div></div><div class=metric><b>${esc(String(job.progress||0))}%</b><div class=sub>progress</div></div><div class=metric><b>${flags.length}</b><div class=sub>final flags</div></div><div class=metric><b>${queue.length}</b><div class=sub>open first</div></div><div class=metric><b>${(sum.unconfirmed_evidence||[]).length}</b><div class=sub>fragments</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${files.length}</b><div class=sub>files</div></div><div class=metric><b>${(sum.workflow_evidence||[]).length}</b><div class=sub>evidence</div></div></div><h3>Workflow Map</h3>${finalWorkflowMap(sum)}<h3>Top submit candidates</h3>${flags.slice(0,10).map(f=>`<div class=flag>${esc(f)} <button type=button class=btn onclick="copyText('${escAttr(f)}')">copy flag</button></div>`).join('')||'<p class=warn>No final strict flag yet. Use Open First and Fragments.</p>'}`;
}
function finalOpenFirst(sum){
 const queue=sum.final_open_queue||sum.priority_artifacts||sum.human_review_artifacts||[];
 return `<h3>Open First</h3><p class=sub>Start here. These are ranked by workflow evidence, visual/manual usefulness, transform signal, and candidate source paths.</p>${finalArtifactCards(queue,120)}<h3>Next Actions</h3>${sloperNextActionsHtml((sum.sloper93_next_actions||sum.workflow_steps||[]).slice(0,40))}<h3>Workflow Evidence</h3>${(sum.workflow_evidence||[]).slice(0,60).map(e=>{const val=finalVal(e);return `<div class=find><div class=row><span class=score>${e.score||0}</span><b>${esc(val)}</b>${val?`<button type=button class=btn onclick="copyText('${escAttr(val)}')">copy</button>`:''}</div><p class=sub>${esc(e.why||'')} - ${esc(e.source||'')}</p>${e.artifact?`<a class=btn target=_blank href="${finalRaw(e.artifact)}">open evidence</a> <button type=button class=btn onclick="copyText('${escAttr(e.artifact)}')">copy path</button>`:''}</div>`}).join('')||'<p class=warn>No workflow evidence yet.</p>'}`;
}
function finalFlags(sum){
 const flags=(sum.flags||[]).map(finalVal).filter(Boolean);
 const strict=sum.unconfirmed_strict_flags||[];
 const rows=[...(sum.unconfirmed_evidence||[]),...(sum.answer_candidates||[]),...(sum.alternate_flag_candidates||[]),...(sum.wrap_candidates||[])];
 const seen=new Set();
 const clean=rows.filter(x=>{const v=String(finalVal(x));const key=v+'|'+String(x.artifact||''); if(!v.trim()||seen.has(key))return false; seen.add(key); return true;}).slice(0,300);
 return `<h3>Final Flags</h3>${flags.map(f=>`<div class=flag>${esc(f)} <button type=button class=btn onclick="copyText('${escAttr(f)}')">copy flag</button></div>`).join('')||'<p class=warn>No final strict flag yet.</p>'}<h3>Unconfirmed Strict Flags</h3>${strict.slice(0,80).map(x=>{const f=finalVal(x);return `<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(f)}</b><button type=button class=btn onclick="copyText('${escAttr(f)}')">copy</button></div><p class=sub>${esc(x.why||'Preserved for review.')}</p>${x.artifact?`<a class=btn target=_blank href="${finalRaw(x.artifact)}">open evidence</a>`:''}</div>`}).join('')||'<p class=warn>No strict-looking unconfirmed flags.</p>'}<h3>Fragments / Bare Braces / Leetspeak</h3>${clean.map(x=>{const v=finalVal(x);const wrap=x.wrapped_if_required||((x.body&&!String(v).toLowerCase().startsWith('ctf_cs{'))?`ctf_cs{${String(x.body).toLowerCase()}}`:'');return `<div class=find><div class=row><span class=score>${x.score||0}</span><b>${esc(v)}</b><button type=button class=btn onclick="copyText('${escAttr(v)}')">copy</button>${wrap?`<button type=button class=btn onclick="copyText('${escAttr(wrap)}')">copy ctf_cs</button>`:''}<span class=pill>${esc(x.bucket||x.priority||'candidate')}</span></div><p class=sub>${esc(x.why||x.why_not_promoted||x.source||'Preserved for human review.')}</p>${x.artifact?`<a class=btn target=_blank href="${finalRaw(x.artifact)}">open evidence</a> <button type=button class=btn onclick="copyText('${escAttr(x.artifact)}')">copy path</button>`:''}</div>`}).join('')||'<p class=warn>No fragments yet.</p>'}`;
}
function finalArtifactHub(sum){
 const hub=sum.final_artifact_hub||sum.sloper93_artifact_hub||sum.sloper100_artifact_hub||{};
 const groups=hub.groups||{};
 const names=[['start_here','Start Here'],['transforms','Transforms / Child Files'],['visual','Visual / Image'],['crypto_decode','Crypto / Decode'],['archives','Archives / Carves'],['network','PCAP / Network'],['reversing','Reversing / Binary'],['misc','Misc']];
 return `<h3>Artifact Hub</h3><p class=sub>Everything generated by transformations stays downloadable. Use search, open, download, and copy path.</p>${names.map(([k,label])=>`<details ${k==='start_here'?'open':''}><summary>${label} (${(groups[k]||[]).length})</summary>${finalArtifactCards(groups[k]||[],90)}</details>`).join('')}<h3>All high-value artifacts</h3>${finalArtifactCards(sum.artifacts||[],260)}`;
}
function finalTransforms(sum){
 const arts=(sum.artifacts||[]).filter(a=>String(`${a.kind} ${a.name} ${a.source} ${a.note}`).toLowerCase().match(/final_|transform|decode|decompress|carve|extract|child|xor|array|rot|rail|columnar|lsb|zip|tar|gzip|pcap|dns|http|office|docx|sqlite|payload|manifest/));
 return `<h3>Transform Chain Outputs</h3><p class=sub>Generated files from logical workflows. Open/download these when auto-ranking is uncertain.</p>${finalArtifactCards(arts,320)}`;
}
function finalFiles(files){
 files=files||[];
 const kinds=[...new Set(files.map(f=>f.kind||'generic'))];
 const shown=files.map((f,i)=>({...f,_idx:i})).filter(f=>(fileKindFilter==='all'||f.kind===fileKindFilter)&&(!fileSearch||(`${f.rel} ${f.name} ${f.kind}`.toLowerCase().includes(fileSearch.toLowerCase()))));
 return `<div class=row><input class=search placeholder="Search files..." value="${escAttr(fileSearch)}" oninput="fileSearch=this.value;renderProject()"><select onchange="fileKindFilter=this.value;renderProject()"><option value=all>all kinds</option>${kinds.map(k=>`<option value="${escAttr(k)}" ${fileKindFilter===k?'selected':''}>${esc(k)}</option>`).join('')}</select><span class=pill>${shown.length}/${files.length}</span></div><div class=grid2><div class=fileList>${shown.map(f=>`<div class="fileMini ${f._idx===selectedFile?'active':''}" onclick="selectFile(${f._idx})"><b>${esc(f.rel||f.name)}</b><div class=sub>${esc(f.kind||'generic')} - ${f.size||0} bytes</div><span class=pill>${(f.flags||[]).length} flags</span><span class=pill>${(f.unconfirmed_evidence||[]).length+(f.answer_candidates||[]).length} candidates</span><span class=pill>${(f.artifacts||[]).length} artifacts</span></div>`).join('')||'<p class=warn>No files match filter.</p>'}</div><div>${fileDetail(files[selectedFile]||shown[0])}</div></div>`;
}
loadProjects=async function(){
 try{
  const r=await fetch('/api/projects'); const j=await r.json();
  projectList.innerHTML=(j.projects||[]).map(p=>{const s=p.summary||{},flags=s.flags||[],queue=s.final_open_queue||s.priority_artifacts||[],arts=s.artifacts||[]; const cls=(typeof v98ProjectStateClass==='function')?v98ProjectStateClass(p):''; return `<div class="project ${cls}"><div class=row><b>${esc(p.title)}</b><span class=pill>${esc(p.category||'auto')}</span><span class=pill>${esc(p.runtime_status||'idle')}</span><span class=pill>${p.progress||0}%</span><span class=pill>${flags.length} flags</span><span class=pill>${queue.length} open first</span><span class=pill>${arts.length} artifacts</span></div><div class=progress><div class="bar ${cls}" style="width:${p.progress||0}%"></div></div><div class=sub>${esc(p.stage||'')}</div><button type=button class=btn onclick="openProject('${p.id}')">Open</button><button type=button class=btn onclick="startProject('${p.id}')">Run</button><button type=button class=btn onclick="stopProject('${p.id}')">Stop</button></div>`}).join('');
 }catch(e){projectList.innerHTML=`<p class=bad>Project list failed: ${esc(String(e))}</p>`}
}
renderProject=function(){
 const j=currentData||{},rep=j.report||{},meta=j.project||{},job=j.job||{},files=rep.files||[],sum=rep.summary||{};
 if(selectedFile>=files.length)selectedFile=0;
 const tabs=['Brief','Open First','Flags','Artifacts','Transforms','Files','Health','Logs'];
 const flags=(sum.flags||[]).map(finalVal).filter(Boolean);
 const body=[
  finalBrief(meta,sum,job,files),
  finalOpenFirst(sum),
  finalFlags(sum),
  finalArtifactHub(sum),
  finalTransforms(sum),
  finalFiles(files),
  sloper88Health(job,sum),
  `<div class=row><button type=button class=btn onclick="copyText('${escAttr(j.log||'')}')">copy log tail</button><a class=btn target=_blank href="/api/projects/${encodeURIComponent(meta.id||current)}/log">open log endpoint</a></div><pre>${esc(j.log||'')}</pre>`
 ];
 projectView.innerHTML=`<div class=card><div class=row between><div><h2>${esc(meta.title||'Project')}</h2><p class=sub>${esc(meta.id||'')} - ${esc(meta.category||'auto')}</p></div><div class=row><button type=button class="btn primary" onclick="startProject('${meta.id}')">Run AutoSolve</button><button type=button class=btn onclick="stopProject('${meta.id}')">Stop project</button><span class=pill>runtime ${esc(sloper88Runtime(job))}</span></div></div><div class=grid3><div class=metric><b>${job.progress||0}%</b><div class=sub>progress</div></div><div class=metric><b>${flags.length}</b><div class=sub>final flags</div></div><div class=metric><b>${(sum.final_open_queue||sum.priority_artifacts||[]).length}</b><div class=sub>open first</div></div><div class=metric><b>${(sum.unconfirmed_evidence||[]).length}</b><div class=sub>fragments</div></div><div class=metric><b>${(sum.artifacts||[]).length}</b><div class=sub>artifacts</div></div><div class=metric><b>${files.length}</b><div class=sub>files</div></div></div><div class=progress><div class=bar style="width:${job.progress||0}%"></div></div><div class=row><span class=pill>${esc(job.status||'idle')}</span><span class=pill>${esc(job.stage||'')}</span></div></div><div class=card><div class=tabs>${tabs.map((t,i)=>`<button type=button class="${i===activeProjectTab?'on':''}" onclick="setProjectTab(${i})">${t}</button>`).join('')}</div>${body.map((h,i)=>`<div id=proj${i} class="${activeProjectTab===i?'':'hidden'}">${h}</div>`).join('')}</div>`;
}
/* ==================== end CTF SLOPER FINAL focused operator UI ==================== */

