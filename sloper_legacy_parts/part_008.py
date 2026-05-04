# Auto-split from sloper_legacy_monolith.py lines 6972-...
def af_parse_embedded_files(report, root, data, label="file"):
    arts = []
    # ZIP signatures
    try:
        bio = io.BytesIO(data)
        if zipfile.is_zipfile(bio):
            bio.seek(0)
            outdir = root/"generated"/"agentforge"/safe(report.get("name","file"))/"embedded_zip"
            outdir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(bio) as z:
                for info in z.infolist()[:80]:
                    if info.is_dir(): continue
                    raw = z.read(info)
                    dest = outdir / safe(Path(info.filename).name or "member.bin")
                    dest.write_bytes(raw)
                    art = {"kind":"agentforge_embedded_zip_member","name":dest.name,"path":str(dest),"url":"/api/raw?path="+str(dest),"source":"AgentForge","score":125,"note":"Extracted embedded zip member","exists":True,"size":dest.stat().st_size,"file":report.get("rel","")}
                    report.setdefault("artifacts",[]).append(art)
                    report.setdefault("transformations",[]).append(art)
                    arts.append(art)
                    txt = raw.decode("utf-8","ignore")
                    if txt:
                        af_run_text_decoders(report, root, txt, "embedded_zip:"+dest.name, 700)
                    af_decompress_recursive(report, root, raw, "embedded_zip_"+dest.name, 0, 2)
    except Exception as e:
        pass
    # PNG appended data / generic appended zip
    try:
        sigs = [(b"PK\x03\x04","zip"), (b"\x1f\x8b\x08","gzip")]
        for sig, nm in sigs:
            idx = data.find(sig, 1)
            if idx > 0:
                raw = data[idx:]
                art = af_art(root, report, f"embedded_{nm}_at_{idx}.bin", raw, "agentforge_embedded_blob", 120, f"Embedded {nm} signature at offset {idx}")
                if art:
                    arts.append(art)
                    af_parse_embedded_files(report, root, raw, "embedded_"+nm)
                    af_decompress_recursive(report, root, raw, "embedded_"+nm, 0, 2)
    except Exception:
        pass
    return arts
def af_crypto_agent(report, root, data, text):
    af_trace(report, "CryptoAgent start", "base/hex/jwt/xor/rsa/hash/classical", 40)
    af_run_text_decoders(report, root, text, "CryptoAgent text", 1800)
    # JWT
    try:
        jwt_items = dp_jwt_decode(text)[:40]
        af_add_chain(report, jwt_items, 50)
        if jwt_items:
            af_trace(report, "CryptoAgent jwt", f"{len(jwt_items)} JWT items", 90)
    except Exception:
        pass
    # XOR
    try:
        items = mb_xor_short_keys(data)
        af_add_chain(report, items, 60)
        if items:
            af_trace(report, "CryptoAgent xor", f"{len(items)} XOR candidates", 90)
    except Exception:
        pass
    # RSA params summary artifact
    try:
        clues = detect_structured_clues(text) if "detect_structured_clues" in globals() else []
        rsa = [c for c in clues if str(c.get("type","")).startswith("rsa")]
        if rsa:
            af_art(root, report, "rsa_structured_clues.json", json.dumps(rsa, indent=2, ensure_ascii=False), "agentforge_rsa_clues", 120, "RSA-like parameters found")
    except Exception:
        pass
def af_forensics_agent(report, root, data, text):
    af_trace(report, "ForensicsAgent start", "decompress/embedded/filesystem/logs", 40)
    af_decompress_recursive(report, root, data, report.get("name","file"), 0, 3)
    af_parse_embedded_files(report, root, data, report.get("name","file"))
    try:
        rb_enhance_report(root, report, data)
    except Exception:
        pass
    try:
        cs_enhance_report(root, report, data)
    except Exception:
        pass
    af_run_text_decoders(report, root, text, "ForensicsAgent text/log", 1200)
def af_pcap_agent(report, root, data, text):
    af_trace(report, "PcapAgent start", "pcap strings, http/dns, scalar fields", 40)
    try:
        arts = cs_pcap_scalar_artifacts(root, report, data) + rb_pcap_fallback_artifacts(root, report, data)
        for a in arts:
            if a.get("path") not in {x.get("path") for x in report.get("artifacts",[])}:
                report.setdefault("artifacts",[]).append(a)
                report.setdefault("transformations",[]).append(a)
        af_trace(report, "PcapAgent artifacts", f"{len(arts)} pcap artifacts", 90 if arts else 20)
    except Exception as e:
        af_trace(report, "PcapAgent failed", str(e))
    # tshark if available, bounded
    p = Path(report.get("path",""))
    if exists("tshark") and p.exists():
        cmds = [
            ("tshark_http", ["tshark","-r",str(p),"-Y","http","-T","fields","-e","frame.number","-e","ip.src","-e","ip.dst","-e","http.host","-e","http.request.uri","-e","http.cookie"]),
            ("tshark_dns", ["tshark","-r",str(p),"-Y","dns","-T","fields","-e","frame.number","-e","ip.src","-e","ip.dst","-e","dns.qry.name"]),
            ("tshark_tcp", ["tshark","-r",str(p),"-Y","tcp","-T","fields","-e","frame.number","-e","ip.src","-e","ip.dst","-e","tcp.srcport","-e","tcp.dstport","-e","tcp.len"]),
        ]
        for name, cmd in cmds:
            try:
                r = run(cmd, 15)
                report.setdefault("outputs",[]).append({"tool":"agentforge_"+name,"ok":r.get("ok"),"cmd":r.get("cmd"),"out":r.get("out")[:80000]})
                af_run_text_decoders(report, root, r.get("out",""), "PcapAgent:"+name, 500)
            except Exception:
                pass
def af_rev_agent(report, root, data, text):
    af_trace(report, "RevAgent start", "strings/constants/pyc/safe static", 40)
    p = Path(report.get("path",""))
    # Safe pyc
    try:
        arts = cs_pyc_decode_artifacts(root, report, data) + rb_pyc_static_artifact(root, report, data)
        for a in arts:
            if a.get("path") not in {x.get("path") for x in report.get("artifacts",[])}:
                report.setdefault("artifacts",[]).append(a)
                report.setdefault("transformations",[]).append(a)
        if arts:
            af_trace(report, "RevAgent pyc", f"{len(arts)} pyc artifacts", 100)
    except Exception:
        pass
    # Binary strings and rodata/static commands
    for cmdname, cmd in [
        ("readelf_strings", ["strings","-a",str(p)]),
        ("objdump_rodata", ["objdump","-s","-j",".rodata",str(p)]),
        ("readelf_symbols", ["readelf","-Ws",str(p)]),
    ]:
        if p.exists() and (cmd[0]=="strings" or exists(cmd[0])):
            try:
                r = run(cmd, 10)
                report.setdefault("outputs",[]).append({"tool":"agentforge_"+cmdname,"ok":r.get("ok"),"cmd":r.get("cmd"),"out":r.get("out")[:120000]})
                af_run_text_decoders(report, root, r.get("out",""), "RevAgent:"+cmdname, 700)
            except Exception:
                pass
def af_stego_agent(report, root, data, text):
    af_trace(report, "StegoAgent start", "image filters, lsb variants, appended data, exif", 40)
    p = Path(report.get("path",""))
    try:
        if report.get("kind")=="image":
            # visual lab already generates many outputs; ensure LSB variants and appended files.
            if "dp_lsb_bit_order_variants" in globals():
                arts = dp_lsb_bit_order_variants(p, root, report)
                for a in arts:
                    if a.get("path") not in {x.get("path") for x in report.get("artifacts",[])}:
                        report.setdefault("artifacts",[]).append(a)
                        report.setdefault("transformations",[]).append(a)
                af_trace(report, "StegoAgent lsb", f"{len(arts)} LSB artifacts", 100 if arts else 20)
            af_parse_embedded_files(report, root, data, "stego_image")
            if exists("exiftool"):
                r=run(["exiftool",str(p)],8)
                report.setdefault("outputs",[]).append({"tool":"agentforge_exiftool","ok":r.get("ok"),"cmd":r.get("cmd"),"out":r.get("out")})
                af_run_text_decoders(report, root, r.get("out",""), "StegoAgent exif", 500)
    except Exception as e:
        af_trace(report, "StegoAgent failed", str(e))
def af_text_osint_agent(report, root, data, text):
    af_trace(report, "TextOSINTAgent start", "statement/text/urls/coordinates/answers", 40)
    statement = ff_statement_text(report)
    combined = statement + "\n" + text
    af_run_text_decoders(report, root, combined, "TextOSINT statement+text", 1600)
    # Extract URL/coords/questions to artifact for human review.
    urls = re.findall(r"https?://[^\s'\"<>]+", combined)
    coords = re.findall(r"-?\d{1,3}\.\d{3,},\s*-?\d{1,3}\.\d{3,}", combined)
    named = re.findall(r"(?:atsakymas|answer|raktas|key|slapta|secret|kodas|code|token)\s*[:=]\s*([^\n\r]{3,180})", combined, re.I)
    if urls or coords or named:
        obj = {"urls":urls[:200], "coordinates":coords[:200], "named_values":named[:200]}
        af_art(root, report, "text_osint_extracted_clues.json", json.dumps(obj, indent=2, ensure_ascii=False), "agentforge_text_osint_clues", 110, "URLs, coordinates and named values")
def af_evidence_score_candidates(report):
    # Build support map from flags, answers, chains, artifacts, outputs.
    supports = {}
    def add(val, src, score=1):
        val=str(val or "").strip()
        if not val: return
        k=val.lower()
        supports.setdefault(k, {"value":val, "sources":set(), "score":0})
        supports[k]["sources"].add(src)
        supports[k]["score"] += score
    for f in report.get("flags",[]):
        add(f, "promoted_flag", 200)
    for a in report.get("answer_candidates",[]):
        add(a.get("value",""), "answer:"+a.get("source",""), int(a.get("score",0)//5)+10)
    for c in report.get("chain_results",[])[:120]:
        for f in c.get("flags",[]) or []:
            add(f, "chain:"+c.get("type",""), int(c.get("score",0)//4)+50)
    for art in report.get("artifacts",[])[:120]:
        p=Path(art.get("path",""))
        try:
            if p.exists() and p.is_file() and p.stat().st_size < 500000:
                txt=p.read_text(encoding="utf-8",errors="ignore")[:8000]
                for f in vf_primary_flags(txt,limit=10):
                    add(f, "artifact:"+art.get("kind",""), int(art.get("score",0)//4)+60)
        except Exception:
            pass
    out=[]
    for rec in supports.values():
        out.append({"value":rec["value"], "sources":sorted(rec["sources"])[:12], "evidence_score":rec["score"] + 20*len(rec["sources"])})
    out=sorted(out,key=lambda x:x.get("evidence_score",0),reverse=True)[:100]
    report["evidence_scored_candidates"]=out
    return out
def af_aggressive_autosolve_report(report, root, data):
    """Main v35 multi-pass local solver. Safe/static: no random execution of challenge binaries."""
    af_trace(report, "Aggressive AutoSolve start", f"kind={report.get('kind')} size={len(data)}", 50)
    text = data.decode("utf-8","ignore")
    kind = report.get("kind","generic")
    suffix = Path(report.get("path","")).suffix.lower()
    # Always first pass on statement + file text.
    af_text_osint_agent(report, root, data, text)
    # Category/kind agents.
    statement = ff_statement_text(report).lower()
    category = ""
    try:
        category = (jread(root/"project.json",{}).get("category","") or "").lower()
    except Exception:
        pass
    routing = " ".join([kind, suffix, category, statement, report.get("name","").lower()])
    if any(x in routing for x in ["crypto","cipher","xor","rsa","jwt","hash","base","šif","sif"]):
        af_crypto_agent(report, root, data, text)
    if kind in ["archive","generic","text"] or any(x in routing for x in ["forensics","forensic","dd.gz","pcap","log","disk","ataskaita","laiko"]):
        af_forensics_agent(report, root, data, text)
    if kind=="pcap" or suffix in [".pcap",".pcapng"] or "pcap" in routing:
        af_pcap_agent(report, root, data, text)
    if kind in ["binary","python_bytecode"] or suffix in [".pyc",".exe",".elf",".dll"] or any(x in routing for x in ["rev","reverse","program","backdoor","skaičiuotuvas","skaiciuotuvas"]):
        af_rev_agent(report, root, data, text)
    if kind=="image" or suffix in [".png",".jpg",".jpeg",".bmp",".gif",".webp"] or any(x in routing for x in ["stego","image","spalv","žinut","zinut","herbas"]):
        af_stego_agent(report, root, data, text)
    # One extra child pass after all agents created artifacts.
    ff_child_artifact_autopass(root, report, max_children=AGENTFORGE_MAX_CHILDREN)
    # Refresh answers/wrappers/review.
    report["answer_candidates"] = vf_collect_answer_candidates(report)
    report["flag_wrapping_helpers"] = ff_candidate_to_flag_helpers(report)
    af_evidence_score_candidates(report)
    report["autopilot_review"] = ff_autopilot_review(report)
    af_trace(report, "Aggressive AutoSolve done", f"flags={len(report.get('flags',[]))} answers={len(report.get('answer_candidates',[]))} artifacts={len(report.get('artifacts',[]))}", 100)
    return report
def vf_postprocess(report, root):
    if report.get("kind")=="image":
        has_vf=bool(report.get("_visualforge_done")) or any(("VisualForge" in str(a.get("source","")) or "FlowForge" in str(a.get("source","")) or "AgentForge" in str(a.get("source",""))) for a in report.get("artifacts",[]))
        if not has_vf:
            arts, previews = vf_visual_lab(Path(report.get("path","")), root, report)
            existing=set(a.get("path") for a in report.get("artifacts",[]))
            for a in arts:
                if a.get("path") not in existing:
                    report.setdefault("artifacts",[]).append(a); existing.add(a.get("path"))
            report.setdefault("previews",[]).extend(previews)
            report["_visualforge_done"]=True
    data=b""
    try:
        data=Path(report.get("path","")).read_bytes()[:8_000_000]
    except Exception:
        pass
    if not report.get("_agentforge_done"):
        try:
            af_aggressive_autosolve_report(report, root, data)
            report["_agentforge_done"]=True
        except Exception as e:
            af_trace(report, "AgentForge failed", str(e), 0)
    try:
        smartsolve_postprocess(report, root)
    except Exception:
        try: stableworkbench_apply_report_postprocess(report, root)
        except Exception: pass
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    af_evidence_score_candidates(report)
    report["autopilot_review"]=ff_autopilot_review(report)
    return report
def project_summary(reports, meta):
    flags=[]; verified_map={}; kinds={}; evidence=[]; chains=[]; actions=[]; missing=[]; agents=[]; transforms=[]; verifyloops=[]; artifacts=[]; recipes=[]; graphs=[]; answers=[]; wrappers=[]; reviews=[]; traces=[]; evscored=[]
    for r in reports:
        kinds[r.get("kind","?")]=kinds.get(r.get("kind","?"),0)+1
        if "answer_candidates" not in r:
            try: r["answer_candidates"]=vf_collect_answer_candidates(r)
            except Exception: r["answer_candidates"]=[]
        if "flag_wrapping_helpers" not in r:
            try: r["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(r)
            except Exception: r["flag_wrapping_helpers"]=[]
        if "autopilot_review" not in r:
            try: r["autopilot_review"]=ff_autopilot_review(r)
            except Exception: r["autopilot_review"]={}
        reviews.append({"file":r.get("rel"),**(r.get("autopilot_review") or {})})
        for tr in r.get("agent_trace",[])[:120]:
            traces.append({"file":r.get("rel"),**tr})
        for ev in r.get("evidence_scored_candidates",[])[:60]:
            evscored.append({"file":r.get("rel"),**ev})
        for v in r.get("verified_flags_visible",[])[:80]:
            key=(v.get("flag") or "").lower(); vv={"file":r.get("rel"),**v}
            if key and (key not in verified_map or vv.get("score",0)>verified_map[key].get("score",0)): verified_map[key]=vv
        for f in r.get("flags",[])[:100]:
            if smartsolve_strict_target_flag_ok(f): flags.append({"file":r.get("rel"),"flag":f,"score":999,"status":"promoted"})
        for ans in r.get("answer_candidates",[])[:100]: answers.append({"file":r.get("rel"),**ans})
        for h in r.get("flag_wrapping_helpers",[])[:60]: wrappers.append({"file":r.get("rel"),**h})
        for f in r.get("findings",[])[:60]:
            if not is_noisy_candidate_text(f.get("value",""),f.get("why",""),f.get("type","")): evidence.append({"file":r.get("rel"),**f})
        for c in r.get("chain_results",[])[:50]:
            out=(c.get("output","") or "")[:900]
            if c.get("score",0)>70 and not is_noisy_candidate_text(out,c.get("type",""),"chain"):
                chains.append({"file":r.get("rel"),"type":c.get("type"),"source":c.get("chain_source"),"score":c.get("score"),"output":out})
        for s in r.get("next_steps",[])[:8]: actions.append({"file":r.get("rel"),**s})
        for a in r.get("agent_runs",[])[:8]: agents.append({"file":r.get("rel"),"kind":r.get("kind"),**a})
        for t in r.get("transformations",[])[:80]: transforms.append({"file":r.get("rel"),**t})
        if r.get("verifyloop"): verifyloops.append({"file":r.get("rel"),"kind":r.get("kind"),**r.get("verifyloop",{})})
        for art in r.get("artifacts",[])[:320]: artifacts.append(art)
        for rec in r.get("recipe_runs",[])[:10]: recipes.append({"file":r.get("rel"),"kind":r.get("kind"),**rec})
        if r.get("artifact_graph"): graphs.append({"file":r.get("rel"),"graph":r.get("artifact_graph")})
        for o in r.get("outputs",[])[:80]:
            if not o.get("ok") and "not installed" in (o.get("out","").lower()): missing.append((o.get("out","").split() or ["unknown"])[0])
    def dedupe_by(items,keyfn,scorefn=lambda x:x.get("score",0)):
        mp={}
        for x in items:
            k=keyfn(x)
            if k and (k not in mp or scorefn(x)>scorefn(mp[k])): mp[k]=x
        return list(mp.values())
    flags=sorted(dedupe_by(flags,lambda x:(x.get("flag") or "").lower()),key=lambda x:x.get("score",0),reverse=True)[:100]
    answers=sorted(dedupe_by(answers,lambda x:(x.get("value") or "").lower()),key=lambda x:x.get("score",0),reverse=True)[:260]
    wrappers=sorted(dedupe_by(wrappers,lambda x:(x.get("suggested_flag") or "").lower()),key=lambda x:x.get("score",0),reverse=True)[:120]
    evscored=sorted(dedupe_by(evscored,lambda x:(x.get("value") or "").lower(), lambda x:x.get("evidence_score",0)), key=lambda x:x.get("evidence_score",0), reverse=True)[:160]
    verified_all=sorted(verified_map.values(),key=lambda x:x.get("score",0),reverse=True)[:100]
    evidence=sorted(evidence,key=lambda x:x.get("score",0),reverse=True)[:140]
    chains=sorted(chains,key=lambda x:x.get("score",0) or 0,reverse=True)[:140]
    artifacts=sorted(artifacts,key=lambda x:(x.get("exists",False),x.get("score",0),x.get("size",0)),reverse=True)[:1200]
    recipes=sorted(recipes,key=lambda x:x.get("score",0),reverse=True)[:160]
    exact=[f for f in flags if "ctf_cs{" in f.get("flag","").lower()]
    workflow=[]
    if exact: workflow.append({"priority":100,"step":"Submit/check top strict ctf_cs flag.","why":"Primary contest format candidate survived strict filters."})
    elif answers: workflow.append({"priority":97,"step":"Open Answer Candidates and Flag Wrapping Helpers.","why":"No strict flag found; likely answer may need wrapping as ctf_cs{answer}."})
    if evscored: workflow.append({"priority":96,"step":"Open Evidence Scores.","why":"AgentForge ranked candidates by number/quality of supporting sources."})
    if reviews: workflow.append({"priority":95,"step":"Open AutoPilot Review.","why":"AgentForge summarized the next best action per file."})
    if artifacts: workflow.append({"priority":90,"step":"Open Artifacts / Visual Lab outputs.","why":"Generated/transformed/extracted files are collected with open/copy controls."})
    priority=sorted([{"file":r.get("rel"),"kind":r.get("kind"),"flags":len(r.get("flags",[])),"answers":len(r.get("answer_candidates",[])),"wrappers":len(r.get("flag_wrapping_helpers",[])),"verified":len(r.get("verified_flags_visible",[])),"recipes":len(r.get("recipe_runs",[])),"artifacts":len(r.get("artifacts",[])),"findings":len(r.get("findings",[])),"chains":len(r.get("chain_results",[])),"trace":len(r.get("agent_trace",[])),"top_score":max([x.get("score",0) for x in r.get("findings",[])]+[0])} for r in reports],key=lambda x:(x["flags"],x["answers"],x["verified"],x["recipes"],x["top_score"],x["artifacts"]),reverse=True)[:160]
    summary={"flags":flags,"answer_candidates":answers,"flag_wrapping_helpers":wrappers,"evidence_scored_candidates":evscored,"autopilot_reviews":reviews,"agent_trace":traces,"verified_flags":verified_all,"exact_flags":exact,"kinds":kinds,"evidence_board":evidence,"top_findings":evidence,"top_chains":chains,"agents":sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:160],"transformations":sorted(transforms,key=lambda x:x.get("score",0),reverse=True)[:320],"artifacts":artifacts,"recipes":recipes,"artifact_graphs":graphs[:140],"verifyloops":verifyloops[:160],"hypotheses":workflowbrain_project_hypotheses(reports) if "workflowbrain_project_hypotheses" in globals() else [],"workflow_steps":sorted(workflow+actions,key=lambda x:x.get("priority",0),reverse=True)[:180],"missing_tools":sorted(set(missing))[:140],"priority_files":priority}
    summary["health"]=cl_project_health(reports, summary) if "cl_project_health" in globals() else {"status":"solved" if flags else ("answer_candidates" if answers else "needs_review")}
    summary["unresolved_plan"]=cl_unresolved_plan(reports) if "cl_unresolved_plan" in globals() else []
    return summary
async def run_aggressive_agents(background_tasks:BackgroundTasks, pid:str=Form(...)):
    if not pdir(pid).exists():
        return {"ok":False,"error":"project not found"}
    background_tasks.add_task(analyze_project,pid)
    return {"ok":True,"status":"scheduled","message":"Aggressive AgentForge analysis scheduled"}
async def run_file_aggressive_agents(pid:str=Form(...), rel:str=Form(...)):
    root=pdir(pid)
    path=root/rel
    if not path.exists():
        path=root/"files"/rel
    if not path.exists():
        return {"ok":False,"error":"file not found"}
    data=readbytes(path)
    rep=analyze_file(pid,path,root,1,1)
    return {"ok":True,"report":rep}
def wf_add_solve_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    report.setdefault("solve_trace", []).append({
        "stage": str(stage)[:120],
        "detail": str(detail)[:800],
        "confidence": int(confidence or 0),
        "artifact": artifact or "",
        "flag": flag or "",
        "time": now() if "now" in globals() else ""
    })
    try:
        af_trace(report, "WriteupForge:"+str(stage), detail, confidence, artifact)
    except Exception:
        pass
def wf_solution_art(root, report, name, content, kind="writeupforge_artifact", score=100, note=""):
    outdir=root/"generated"/"writeupforge"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"WriteupForge","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        wf_add_solve_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        wf_add_solve_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def wf_ascii_quality(s):
    s=str(s or "")
    if not s:
        return 0
    printable=sum(1 for c in s if 32<=ord(c)<127 or c in "\n\r\t")
    ratio=printable/max(1,len(s))
    score=int(ratio*80)
    low=s.lower()
    if "ctf_cs{" in low: score+=300
    if re.search(r"[a-z0-9]{3,}_[a-z0-9_]{3,}",low): score+=55
    if any(x in low for x in ["flag","answer","atsakymas","raktas","secret","token"]): score+=35
    if len(s)>=8: score+=20
    if len(s)>300: score-=20
    if "�" in s: score-=80
    return score
def wf_extract_ascii_from_u16(vals, endian="little"):
    bs=bytearray()
    for v in vals:
        try:
            v=int(v)&0xffff
        except Exception:
            continue
        if endian=="little":
            bs.extend([v&255,(v>>8)&255])
        else:
            bs.extend([(v>>8)&255,v&255])
    return bytes(bs).decode("utf-8","ignore")
def wf_scan_numeric_tables(data, root, report):
    """Static table agent: scan doubles/ints for coeff*i -> little-endian ASCII and other table encodings."""
    arts=[]; chains=[]
    data=bytes(data or b"")
    candidates=[]
    # Scan aligned double windows. This targets the vibration writeup pattern:
    # int(coeff[i]*i) forms little-endian 16-bit ASCII pairs.
    max_bytes=min(len(data), 6_000_000)
    for step in [8]:
        for off in range(0, max_bytes-8*6, step):
            # Avoid scanning absolutely every window in huge files too expensively.
            if off > 1_500_000 and off % 64 != 0:
                continue
            vals=[]
            ok=True
            for j in range(1, 25):
                pos=off+(j-1)*8
                if pos+8>max_bytes: break
                try:
                    d=struct.unpack("<d", data[pos:pos+8])[0]
                except Exception:
                    ok=False; break
                if not math.isfinite(d) or abs(d)>1e9:
                    ok=False; break
                vals.append(d)
            if len(vals)<6 or not ok:
                continue
            # Try windows 6..24, int(coeff[i]*i)
            for n in range(6, min(24,len(vals))+1):
                products=[int(vals[i-1]*i) & 0xffff for i in range(1,n+1)]
                little=wf_extract_ascii_from_u16(products,"little")
                big=wf_extract_ascii_from_u16(products,"big")
                for endian,txt in [("little",little),("big",big)]:
                    sc=wf_ascii_quality(txt)
                    # Require meaningful signal, not random printable noise.
                    if sc>=115 or vf_primary_flags(txt,limit=2):
                        candidates.append({"offset":off,"count":n,"method":f"double_coeff_times_index_{endian}","text":txt,"score":sc,"values":products})
                        break
    # Scan raw u16 arrays as little/big ASCII pairs.
    for off in range(0, min(max_bytes,2_000_000)-2*8, 2):
        if off>300000 and off%32!=0:
            continue
        vals=[]
        for j in range(0,40):
            pos=off+j*2
            if pos+2>max_bytes: break
            vals.append(int.from_bytes(data[pos:pos+2],"little"))
        if len(vals)>=8:
            txt=wf_extract_ascii_from_u16(vals[:24],"little")
            sc=wf_ascii_quality(txt)
            if sc>=140 or vf_primary_flags(txt,limit=2):
                candidates.append({"offset":off,"count":24,"method":"u16_little_ascii_pairs","text":txt,"score":sc,"values":vals[:24]})
    # Deduplicate and write artifact.
    out=[]; seen=set()
    for c in sorted(candidates,key=lambda x:x.get("score",0),reverse=True):
        key=(c["method"],c["text"][:100])
        if key not in seen:
            seen.add(key); out.append(c)
    out=out[:80]
    if out:
        art=wf_solution_art(root,report,"numeric_table_candidates.json",json.dumps(out,indent=2,ensure_ascii=False),"writeupforge_numeric_table_candidates",180,"Numeric table/static coefficient hidden ASCII candidates")
        if art: arts.append(art)
        for c in out[:20]:
            text=c.get("text","")
            flags=vf_primary_flags(text,limit=5)
            # If table text is flag body style, suggest wrapper; do not promote unless exact ctf_cs.
            if flags:
                for f in flags:
                    if f not in report.setdefault("flags",[]): report["flags"].append(f)
                    wf_add_solve_trace(report,"NumericTableAgent flag",f"{f} from {c['method']} offset {c['offset']}",260,art.get("path") if art else "",f)
            elif re.fullmatch(r"[A-Za-z0-9_\-:.+]{8,120}", text.strip()):
                report.setdefault("answer_candidates",[]).append({"value":text.strip(),"source":"NumericTableAgent:"+c["method"],"why":"Numeric table decoded to flag-body-like ASCII; consider wrapping if challenge expects ctf_cs{...}.","score":210})
                report.setdefault("flag_wrapping_helpers",[]).append({"answer":text.strip(),"suggested_flag":f"ctf_cs{{{text.strip()}}}","source":"NumericTableAgent","score":205,"why":"WriteupForge numeric table produced a likely flag body."})
            chains.append({"type":"writeupforge_numeric_table","input":c["method"],"output":text,"flags":flags,"score":c.get("score",0)+120,"chain_source":f"NumericTableAgent offset={c.get('offset')}"})
    if chains:
        af_add_chain(report,chains,60)
        wf_add_solve_trace(report,"NumericTableAgent",f"{len(out)} numeric table candidates; {len(chains)} chain items",180)
    return arts
PIET_PALETTE_HEX=[
    "#FFC0C0","#FFFFC0","#C0FFC0","#C0FFFF","#C0C0FF","#FFC0FF",
    "#FF0000","#FFFF00","#00FF00","#00FFFF","#0000FF","#FF00FF",
    "#C00000","#C0C000","#00C000","#00C0C0","#0000C0","#C000C0",
    "#FFFFFF","#000000"
]
def wf_piet_palette_rgb():
    out=[]
    for h in PIET_PALETTE_HEX:
        out.append(tuple(int(h[i:i+2],16) for i in (1,3,5)))
    return out
def wf_detect_dot_grid_channel(arr, channel_idx):
    """Find repeated channel-exclusive dot grid. Returns best spec or None."""
    import numpy as _np
    ch=arr[:,:,channel_idx].astype("int32")
    # Look for values near multiples of 12 and local anomalies.
    vals=ch.flatten()
    # Candidate dots: values close to multiples of 12 and not too uniform.
    moddist=_np.minimum(vals%12, 12-(vals%12))
    # Use pixels exactly/near multiples of 12 but exclude overwhelming natural image by local contrast.
    h,w=ch.shape
    # Downsample candidate positions for speed.
    coords=[]
    # local contrast: pixel deviates from 5x5 median-ish using neighbor mean.
    for y in range(1,h-1,1):
        row=ch[y]
        for x in range(1,w-1,1):
            v=int(row[x])
            if min(v%12,12-(v%12))<=1:
                nb=(int(ch[y-1,x])+int(ch[y+1,x])+int(ch[y,x-1])+int(ch[y,x+1]))//4
                if abs(v-nb)>=8:
                    coords.append((x,y,v))
        if len(coords)>20000:
            break
    if len(coords)<20:
        return None
    xs=[c[0] for c in coords]; ys=[c[1] for c in coords]
    # Guess spacing by differences among sorted unique positions.
    def common_spacing(vals):
        u=sorted(set(vals))
        diffs=[]
        last=None
        for v in u:
            if last is not None:
                d=v-last
                if 5<=d<=200:
                    diffs.append(d)
            last=v
        if not diffs:
            return None
        from collections import Counter
        cnt=Counter(diffs)
        return cnt.most_common(1)[0][0]
    sx=common_spacing(xs)
    sy=common_spacing(ys)
    if not sx or not sy:
        return None
    # Try origins from low modulo.
    ox_candidates=list(range(min(sx,10)))
    oy_candidates=list(range(min(sy,10)))
    best=None
    for ox in ox_candidates:
        for oy in oy_candidates:
            cols=(w-ox)//sx
            rows=(h-oy)//sy
            if cols<4 or rows<4 or cols>300 or rows>300:
                continue
            hits=0; total=0; values=[]
            for yy in range(rows):
                y=oy+yy*sy+1
                if y>=h: continue
                for xx in range(cols):
                    x=ox+xx*sx+1
                    if x>=w: continue
                    v=int(ch[y,x]); total+=1
                    if min(v%12,12-(v%12))<=2:
                        hits+=1; values.append(v)
            if total:
                ratio=hits/total
                unique=len(set(round(v/12) for v in values if 0<=round(v/12)<=19))
                score=ratio*100+unique*5+min(cols*rows/50,30)
                if ratio>0.45 and unique>=8 and (best is None or score>best["score"]):
                    best={"channel":channel_idx,"origin":(ox,oy),"step":(sx,sy),"cols":cols,"rows":rows,"score":score,"unique_indices":unique,"ratio":ratio}
    return best
def wf_extract_piet_from_grid(image_path, root, report):
    arts=[]
    try:
        im=Image.open(image_path).convert("RGB")
        arr=np.array(im)
    except Exception:
        return []
    specs=[]
    for ci,name in enumerate(["R","G","B"]):
        try:
            spec=wf_detect_dot_grid_channel(arr,ci)
            if spec:
                spec["channel_name"]=name
                specs.append(spec)
        except Exception:
            pass
    if not specs:
        return []
    spec=sorted(specs,key=lambda x:x["score"],reverse=True)[0]
    palette=wf_piet_palette_rgb()
    ox,oy=spec["origin"]; sx,sy=spec["step"]; cols=spec["cols"]; rows=spec["rows"]; ci=spec["channel"]
    piet=Image.new("RGB",(cols,rows),(255,255,255))
    indices=[]
    for yy in range(rows):
        for xx in range(cols):
            x=min(arr.shape[1]-1,ox+xx*sx+1)
            y=min(arr.shape[0]-1,oy+yy*sy+1)
            v=int(arr[y,x,ci])
            idx=max(0,min(19,int(round(v/12))))
            indices.append(idx)
            piet.putpixel((xx,yy),palette[idx])
    outdir=root/"generated"/"writeupforge"/safe(report.get("name","image"))/"piet_grid"
    outdir.mkdir(parents=True,exist_ok=True)
    p=outdir/"extracted_piet.png"
    piet.save(p)
    art={"kind":"writeupforge_piet_grid_image","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"WriteupForge","score":210,"note":f"Piet grid extracted from {spec['channel_name']} channel step={spec['step']} size={cols}x{rows}","exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
    report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art)
    meta=outdir/"piet_grid_meta.json"
    meta.write_text(json.dumps(spec,indent=2),encoding="utf-8")
    mart={"kind":"writeupforge_piet_grid_meta","name":meta.name,"path":str(meta),"url":"/api/raw?path="+str(meta),"source":"WriteupForge","score":160,"note":"Detected Piet channel grid parameters","exists":True,"size":meta.stat().st_size,"file":report.get("rel","")}
    report.setdefault("artifacts",[]).append(mart); report.setdefault("transformations",[]).append(mart); arts.append(mart)
    wf_add_solve_trace(report,"PietGridAgent",f"Extracted Piet grid from {spec['channel_name']} channel, {cols}x{rows}, step={spec['step']}, origin={spec['origin']}",210,str(p))
    # If npiet exists, run it bounded.
    if exists("npiet"):
        try:
            r=run(["npiet",str(p)],15)
            report.setdefault("outputs",[]).append({"tool":"writeupforge_npiet","ok":r.get("ok"),"cmd":r.get("cmd"),"out":r.get("out")[:20000]})
            af_run_text_decoders(report,root,r.get("out",""),"npiet extracted_piet",800)
            for f in vf_primary_flags(r.get("out",""),limit=10):
                if f not in report.setdefault("flags",[]): report["flags"].append(f)
                wf_add_solve_trace(report,"PietGridAgent npiet flag",f,260,str(p),f)
        except Exception as e:
            wf_add_solve_trace(report,"PietGridAgent npiet failed",str(e),0,str(p))
    else:
        wf_add_solve_trace(report,"PietGridAgent next step","Install/run npiet on extracted_piet.png; artifact is ready.",150,str(p))
    return arts
def wf_tile_puzzle_artifacts(image_path, root, report):
    arts=[]
    try:
        im=Image.open(image_path).convert("RGB")
    except Exception:
        return []
    w,h=im.size
    # Common CTF tile sizes: 16x16 grid, or dimensions divisible by 8/10/12/16.
    candidates=[]
    for cols in [16,12,10,8,20]:
        if w%cols==0:
            tw=w//cols
            for rows in [16,12,10,8,20]:
                if h%rows==0:
                    th=h//rows
                    if 24<=tw<=400 and 24<=th<=400 and 16<=cols*rows<=500:
                        candidates.append((cols,rows,tw,th))
    if not candidates:
        return []
    # Choose 16x16 if possible, else closest to square 100-300 tiles.
    candidates=sorted(candidates,key=lambda x:(0 if x[0]==16 and x[1]==16 else 1, abs((x[0]*x[1])-256), x[0]*x[1]))
    cols,rows,tw,th=candidates[0]
    outdir=root/"generated"/"writeupforge"/safe(report.get("name","image"))/"tile_puzzle"
    outdir.mkdir(parents=True,exist_ok=True)
    # Contact sheet with index labels approximated by filename metadata (no drawing dependency).
    thumbs=[]
    for ty in range(rows):
        for tx in range(cols):
            tile=im.crop((tx*tw,ty*th,(tx+1)*tw,(ty+1)*th))
            tile.thumbnail((120,80))
            thumbs.append((tx,ty,tile.copy()))
    sheet=Image.new("RGB",(cols*130,rows*100),(10,15,10))
    for tx,ty,tile in thumbs:
        sheet.paste(tile,(tx*130+5,ty*100+5))
    p=outdir/"tile_contact_sheet.png"
    sheet.save(p)
    art={"kind":"writeupforge_tile_contact_sheet","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"WriteupForge","score":145,"note":f"Tile contact sheet for possible shuffled puzzle: grid {cols}x{rows}, tile {tw}x{th}","exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
    report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art)
    # Edge matching hints: compute average edge colors and nearest neighbors.
    import numpy as _np
    tiles=[]
    for ty in range(rows):
        for tx in range(cols):
            tile=np.array(im.crop((tx*tw,ty*th,(tx+1)*tw,(ty+1)*th))).astype("float32")
            idx=ty*cols+tx
            tiles.append({
                "idx":idx,"x":tx,"y":ty,
                "left":tile[:,0,:].mean(axis=0).tolist(),
                "right":tile[:,-1,:].mean(axis=0).tolist(),
                "top":tile[0,:,:].mean(axis=0).tolist(),
                "bottom":tile[-1,:,:].mean(axis=0).tolist()
            })
    def dist(a,b):
        return float(sum((a[i]-b[i])**2 for i in range(3))**0.5)
    hints=[]
    for t in tiles[:500]:
        right=sorted(((dist(t["right"],u["left"]),u["idx"]) for u in tiles if u["idx"]!=t["idx"]),key=lambda x:x[0])[:5]
        bottom=sorted(((dist(t["bottom"],u["top"]),u["idx"]) for u in tiles if u["idx"]!=t["idx"]),key=lambda x:x[0])[:5]
        hints.append({"idx":t["idx"],"grid":[t["x"],t["y"]],"best_right":right,"best_bottom":bottom})
    hp=outdir/"tile_edge_match_hints.json"
    hp.write_text(json.dumps({"grid":[cols,rows],"tile":[tw,th],"hints":hints[:500]},indent=2),encoding="utf-8")
    hart={"kind":"writeupforge_tile_edge_hints","name":hp.name,"path":str(hp),"url":"/api/raw?path="+str(hp),"source":"WriteupForge","score":140,"note":"Edge-color nearest-neighbor hints for manual tile reconstruction","exists":True,"size":hp.stat().st_size,"file":report.get("rel","")}
    report.setdefault("artifacts",[]).append(hart); report.setdefault("transformations",[]).append(hart); arts.append(hart)
    wf_add_solve_trace(report,"TilePuzzleAgent",f"Created tile contact sheet and edge hints: grid {cols}x{rows}, tile {tw}x{th}",150,str(p))
    return arts
def wf_zsteg_like_lsb_extract(image_path, root, report):
    arts=[]
    try:
        im=Image.open(image_path).convert("RGB")
        arr=np.array(im)
    except Exception:
        return []
    outdir=root/"generated"/"writeupforge"/safe(report.get("name","image"))/"lsb_streams"
    outdir.mkdir(parents=True,exist_ok=True)
    channels={"r":0,"g":1,"b":2}
    for cname,ci in channels.items():
        for bit in [0,1]:
            bits=(arr[:,:,ci]>>bit)&1
            for order in ["xy","yx"]:
                flat=bits.flatten() if order=="xy" else bits.T.flatten()
                # group bits into bytes lsb-first and msb-first
                for endian in ["lsbfirst","msbfirst"]:
                    bs=bytearray()
                    for i in range(0,len(flat)-7,8):
                        chunk=flat[i:i+8]
                        if endian=="lsbfirst":
                            val=sum(int(chunk[j])<<j for j in range(8))
                        else:
                            val=0
                            for j in range(8): val=(val<<1)|int(chunk[j])
                        bs.append(val)
                    txt=bytes(bs).decode("utf-8","ignore")
                    sc=wf_ascii_quality(txt[:8000])
                    if sc>=110 or vf_primary_flags(txt,limit=3):
                        name=f"lsb_b{bit+1}_{cname}_{order}_{endian}.txt"
                        p=outdir/name
                        p.write_text(txt[:200000],encoding="utf-8",errors="ignore")
                        art={"kind":"writeupforge_lsb_stream","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"WriteupForge","score":sc+70,"note":f"zsteg-like stream b{bit+1},{cname},lsb,{order},{endian}","exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
                        report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art)
                        for f in vf_primary_flags(txt,limit=10):
                            if f not in report.setdefault("flags",[]): report["flags"].append(f)
                            wf_add_solve_trace(report,"LSBAgent flag",f"{f} via {name}",240,str(p),f)
                        af_run_text_decoders(report,root,txt[:50000],"lsb_stream:"+name,700)
    if arts:
        wf_add_solve_trace(report,"LSBAgent",f"Generated {len(arts)} high-signal LSB stream artifacts",170)
    return arts
def wf_writeup_agents(report, root, data):
    kind=report.get("kind","generic")
    p=Path(report.get("path",""))
    wf_add_solve_trace(report,"WriteupForge start",f"kind={kind}, file={p.name}",60)
    # Static numeric/binary analysis for reverse tasks.
    if kind in ["binary","generic","python_bytecode"] or p.suffix.lower() in [".exe",".dll",".elf",".bin",".dat",".so",".pyc"]:
        wf_scan_numeric_tables(data,root,report)
    # Image stego writeup agents.
    if kind=="image" or p.suffix.lower() in [".png",".jpg",".jpeg",".bmp",".webp"]:
        wf_extract_piet_from_grid(p,root,report)
        wf_tile_puzzle_artifacts(p,root,report)
        wf_zsteg_like_lsb_extract(p,root,report)
    # Tighten answers and evidence after writeup-specific agents.
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    try:
        af_evidence_score_candidates(report)
    except Exception:
        pass
    report["autopilot_review"]=ff_autopilot_review(report)
    return report
_old_af_aggressive = af_aggressive_autosolve_report
def af_aggressive_autosolve_report(report, root, data):
    report=_old_af_aggressive(report,root,data)
    try:
        wf_writeup_agents(report,root,data)
    except Exception as e:
        wf_add_solve_trace(report,"WriteupForge failed",str(e),0)
    return report
def wf_flag_has_solve_evidence(report, flag):
    flag=str(flag or "")
    if not smartsolve_strict_target_flag_ok(flag):
        return False
    # Strong exact evidence from real solve artifacts/chains.
    low=flag.lower()
    support=0
    sources=[]
    for c in report.get("chain_results",[])[:200]:
        if low in str(c.get("output","")).lower() or flag in (c.get("flags") or []):
            support+=2; sources.append("chain:"+str(c.get("type","")))
    for a in report.get("artifacts",[])[:250]:
        p=Path(a.get("path",""))
        try:
            if p.exists() and p.is_file() and p.stat().st_size<600000:
                txt=p.read_text(encoding="utf-8",errors="ignore")
                if low in txt.lower():
                    support+=2; sources.append("artifact:"+str(a.get("kind","")))
        except Exception:
            pass
    for t in report.get("solve_trace",[])+report.get("agent_trace",[]):
        if low in str(t).lower():
            support+=1; sources.append("trace")
    # Original strings alone are not enough if there is no chain/artifact/trace.
    report.setdefault("flag_evidence",{})[flag]={"support":support,"sources":sources[:12]}
    return support>=2
def vf_postprocess(report, root):
    # Run original v35 postprocess, then writeup agents and stricter evidence classification.
    if report.get("kind")=="image":
        has_vf=bool(report.get("_visualforge_done")) or any(("VisualForge" in str(a.get("source","")) or "FlowForge" in str(a.get("source","")) or "AgentForge" in str(a.get("source","")) or "WriteupForge" in str(a.get("source",""))) for a in report.get("artifacts",[]))
        if not has_vf:
            arts, previews = vf_visual_lab(Path(report.get("path","")), root, report)
            existing=set(a.get("path") for a in report.get("artifacts",[]))
            for a in arts:
                if a.get("path") not in existing:
                    report.setdefault("artifacts",[]).append(a); existing.add(a.get("path"))
            report.setdefault("previews",[]).extend(previews)
            report["_visualforge_done"]=True
    data=b""
    try:
        data=Path(report.get("path","")).read_bytes()[:8_000_000]
    except Exception:
        pass
    if not report.get("_agentforge_done"):
        try:
            _old_af_aggressive(report, root, data)
            report["_agentforge_done"]=True
        except Exception as e:
            af_trace(report, "AgentForge failed", str(e), 0)
    if not report.get("_writeupforge_done"):
        try:
            wf_writeup_agents(report,root,data)
            report["_writeupforge_done"]=True
        except Exception as e:
            wf_add_solve_trace(report,"WriteupForge failed",str(e),0)
    try:
        smartsolve_postprocess(report, root)
    except Exception:
        try: stableworkbench_apply_report_postprocess(report, root)
        except Exception: pass
    # Split exact flags into strong and weak evidence. Weak flags still visible but not "solved".
    all_flags=list(dict.fromkeys([f for f in report.get("flags",[]) if smartsolve_strict_target_flag_ok(f)]))
    strong=[]; weak=[]
    for f in all_flags:
        if wf_flag_has_solve_evidence(report,f):
            strong.append(f)
        else:
            weak.append(f)
    report["flags"]=strong
    report["weak_flag_candidates"]=[{"flag":f, **report.get("flag_evidence",{}).get(f,{})} for f in weak]
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    try: af_evidence_score_candidates(report)
    except Exception: pass
    report["autopilot_review"]=ff_autopilot_review(report)
    return report
