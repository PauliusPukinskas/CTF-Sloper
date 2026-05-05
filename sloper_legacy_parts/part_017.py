# Auto-split from sloper_legacy_monolith.py lines 15042-...
def sl47_reconstruct_artifact_log(text):
    import json as _json
    objs=[]
    for ln in str(text or "").splitlines():
        try:
            o=_json.loads(ln)
            if isinstance(o,dict) and "x" in o and "y" in o and "rows" in o:
                objs.append(o)
        except Exception:
            pass
    if not objs:
        return None
    maxx=max(int(o.get("x",0))+max([len(r) for r in o.get("rows",[""])]+[0]) for o in objs)+2
    maxy=max(int(o.get("y",0))+len(o.get("rows",[])) for o in objs)+2
    maxx=min(max(maxx,20),360)
    maxy=min(max(maxy,5),80)
    raw=[[" "]*maxx for _ in range(maxy)]
    filtered=[[" "]*maxx for _ in range(maxy)]
    allowed=set("$ _/\\|")
    kept=0
    skipped=0
    for o in objs:
        x=int(o.get("x",0)); y=int(o.get("y",0)); rows=o.get("rows",[])
        txt="".join(rows)
        good=sum(ch in allowed for ch in txt)
        bad=sum(ch not in allowed for ch in txt)
        is_ascii_art=good >= max(4,bad*2)
        if is_ascii_art: kept+=1
        else: skipped+=1
        for dy,row in enumerate(rows):
            for dx,ch in enumerate(str(row)):
                xx=x+dx; yy=y+dy
                if 0<=yy<maxy and 0<=xx<maxx and ch!=" ":
                    raw[yy][xx]=ch
                    if is_ascii_art:
                        filtered[yy][xx]=ch
    def trim(canvas):
        lines=["".join(r).rstrip() for r in canvas]
        while lines and not lines[-1].strip():
            lines.pop()
        return "\n".join(lines)
    return {
        "object_count":len(objs),
        "kept_ascii_art_blocks":kept,
        "skipped_noise_blocks":skipped,
        "raw_canvas":trim(raw),
        "noise_filtered_canvas":trim(filtered),
    }
def sl47_artifact_log_agent(report, root, data):
    text=data[:2_000_000].decode("utf-8","ignore")
    if not sl47_is_artifact_json_log(text):
        return []
    rec=sl47_reconstruct_artifact_log(text)
    if not rec:
        return []
    arts=[]
    art1=sl47_art(root,report,"artifact_log_noise_filtered_canvas.txt",rec["noise_filtered_canvas"],"sloper47_artifact_log_canvas",310,"Noise-filtered ASCII art reconstruction from JSON coordinate log.")
    art2=sl47_art(root,report,"artifact_log_raw_canvas.txt",rec["raw_canvas"],"sloper47_artifact_log_raw_canvas",210,"Raw overlaid canvas from JSON coordinate log.")
    art3=sl47_art(root,report,"artifact_log_reconstruction_manifest.json",json.dumps({k:v for k,v in rec.items() if k not in ["raw_canvas","noise_filtered_canvas"]},indent=2,ensure_ascii=False),"sloper47_artifact_log_manifest",260,"Artifact log reconstruction stats.")
    for a in [art1,art2,art3]:
        if a: arts.append(a)
    # Promote exact/braced text if the ASCII art already contains it; usually this is for human OCR.
    try:
        sl45_promote_answer_markers(report,rec["noise_filtered_canvas"],"SLOPER v47 ArtifactLog",art1.get("path") if art1 else "",280)
    except Exception:
        pass
    report.setdefault("next_steps",[]).insert(0,{"priority":96,"step":"Open artifact_log_noise_filtered_canvas.txt.","why":"v47 removed random symbol noise and reconstructed the readable ASCII art canvas."})
    sl47_trace(report,"ArtifactLog",f"reconstructed canvas from {rec['object_count']} JSON rows; kept {rec['kept_ascii_art_blocks']} art blocks",310,art1.get("path") if art1 else "")
    return arts
def sl47_is_time_log(text):
    sample=str(text or "")[:10000]
    return bool(re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",sample)) and ("Time" in sample or "Heartbeat" in sample or "WARN" in sample)
def sl47_time_anomaly_agent(report, root, data):
    import datetime as _dt, collections as _collections
    text=data[:3_000_000].decode("utf-8","ignore")
    if not sl47_is_time_log(text):
        return []
    events=[]
    for ln in text.splitlines():
        m=re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:(\d{2})Z)\s+(\S+)\s+(\S+)\s*(.*)",ln)
        if m:
            ts=_dt.datetime.fromisoformat(m.group(1).replace("Z","+00:00"))
            events.append({"ts":m.group(1),"dt":ts,"sec":int(m.group(2)),"module":m.group(3),"level":m.group(4),"msg":m.group(5),"line":ln})
    if len(events)<5:
        return []
    deltas=[]
    for a,b in zip(events,events[1:]):
        deltas.append(int((b["dt"]-a["dt"]).total_seconds()))
    anomaly=[]
    for i,d in enumerate(deltas,1):
        if d not in (1,2):
            anomaly.append({"index":i,"delta":d,**{k:v for k,v in events[i].items() if k!="dt"}})
    def bits_to_ascii(bits):
        out=[]
        for i in range(0,len(bits)-7,8):
            try:
                v=int(bits[i:i+8],2)
                out.append(chr(v) if 32<=v<127 else ".")
            except Exception:
                pass
        return "".join(out)
    candidates=[]
    vals=[a["delta"] for a in anomaly]
    maps=[{-1:"0",3:"1"},{-1:"1",3:"0"}]
    for mp in maps:
        bits="".join(mp.get(v,"") for v in vals)
        if len(bits)>=8:
            candidates.append({"method":f"delta_map_{mp}","bits_len":len(bits),"ascii":bits_to_ascii(bits)})
    # module/level numeric sequences over anomaly rows.
    modules=sorted(set(e["module"] for e in events))
    levels=sorted(set(e["level"] for e in events))
    mod_index={m:i for i,m in enumerate(modules)}
    lvl_index={m:i for i,m in enumerate(levels)}
    for name,seq in [
        ("anomaly_seconds",[a["sec"] for a in anomaly]),
        ("anomaly_module_index",[mod_index.get(a["module"],0) for a in anomaly]),
        ("anomaly_level_index",[lvl_index.get(a["level"],0) for a in anomaly]),
    ]:
        ascii_low="".join(chr(x&255) if 32<=x&255<127 else "." for x in seq[:2000])
        candidates.append({"method":name,"count":len(seq),"ascii_low":ascii_low,"values":seq[:400]})
    report_obj={
        "event_count":len(events),
        "delta_counts":dict(_collections.Counter(deltas)),
        "anomaly_count":len(anomaly),
        "modules":modules,
        "levels":levels,
        "candidates":candidates,
        "anomaly_rows":anomaly[:600],
    }
    arts=[]
    art=sl47_art(root,report,"time_anomaly_report.json",json.dumps(report_obj,indent=2,ensure_ascii=False,default=str),"sloper47_time_anomaly_report",300,"Timestamp anomaly report with delta/module/level candidate decodes.")
    if art: arts.append(art)
    for c in candidates:
        for field in ["ascii","ascii_low"]:
            txt=c.get(field,"")
            if txt and any(x in txt.lower() for x in ["ctf","flag","secret","time","laik","hidden","{"]):
                sl45_promote_answer_markers(report,txt,"SLOPER v47 TimeAnomaly",art.get("path") if art else "",290)
    report.setdefault("next_steps",[]).insert(0,{"priority":94,"step":"Open time_anomaly_report.json.","why":"v47 extracted non-standard timestamp deltas and candidate decodes."})
    sl47_trace(report,"TimeAnomaly",f"{len(events)} events, {len(anomaly)} non-1/2s deltas",300,art.get("path") if art else "")
    return arts
def sl47_fast_log_analyze_file(pid, path, root, i, total):
    p=Path(path); data=p.read_bytes()
    rel=str(p.relative_to(root)) if str(p).startswith(str(root)) else p.name
    report={
        "id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":rel,"kind":"log",
        "size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest(),"magic":data[:32].hex(),
        "flags":[],"weak_flag_candidates":[],"verified_flags":[],"verified_flags_visible":[],"strings":py_strings(data,limit=800),"outputs":[],"previews":[],
        "commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"transformations":[],"findings":[],
        "next_steps":[],"solve_trace":[],"agent_trace":[],"answer_candidates":[],"flag_wrapping_helpers":[],"evidence_scored_candidates":[]
    }
    text=data[:500000].decode("utf-8","ignore")
    sl45_promote_answer_markers(report,text,"SLOPER v47 fast log marker",str(p),240)
    try: sl47_artifact_log_agent(report,root,data)
    except Exception as e: sl47_trace(report,"ArtifactLog failed",str(e),0)
    try: sl47_time_anomaly_agent(report,root,data)
    except Exception as e: sl47_trace(report,"TimeAnomaly failed",str(e),0)
    # Keep exact flags if present, but do not run heavy legacy clue chains.
    try:
        flags=vf_primary_flags(text,limit=20,scan_limit=500000)
        for f in flags:
            if f not in report["flags"]:
                report["flags"].append(f)
    except Exception:
        pass
    if report.get("flags"):
        report["findings"].insert(0,{"score":520,"type":"sloper47_fast_log_flag","value":report["flags"][0],"why":"Fast log path found/promoted a flag."})
    else:
        report["findings"].append({"score":260,"type":"sloper47_fast_log_artifacts","value":f"{len(report.get('artifacts',[]))} artifacts","why":"Fast log path generated bounded reconstruction/anomaly artifacts."})
    return report
def sl47_should_fast_log(path):
    try:
        p=Path(path)
        if p.suffix.lower() not in [".log",".txt",".jsonl"]:
            return False
        data=p.read_bytes()[:20000]
        text=data.decode("utf-8","ignore")
        return sl47_is_artifact_json_log(text) or sl47_is_time_log(text)
    except Exception:
        return False
_prev_analyze_file_v47 = analyze_file
def analyze_file(pid, path, root, i, total):
    try:
        if sl47_should_fast_log(path):
            return sl47_fast_log_analyze_file(pid,path,root,i,total)
    except Exception:
        pass
    return _prev_analyze_file_v47(pid,path,root,i,total)
_prev_project_summary_v47 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v47(reports, meta)
    # Cap noisy wrappers and weak answers while preserving the best candidates.
    helpers=summary.get("flag_wrapping_helpers",[]) or []
    def hscore(h):
        s=int(h.get("score",0) or 0)
        txt=(h.get("suggested_flag","")+" "+h.get("source","")+" "+h.get("why","")).lower()
        if "sha256" in txt: s+=30
        if "placeholder" in txt: s-=500
        return s
    seen=set(); clean=[]
    for h in sorted(helpers,key=hscore,reverse=True):
        sf=h.get("suggested_flag","")
        body=sf[7:-1] if sf.startswith("ctf_cs{") and sf.endswith("}") else sf
        if sl42_is_bad_wrapper_body(body):
            continue
        k=sf.lower()
        if k not in seen:
            seen.add(k); clean.append(h)
        if len(clean)>=80:
            break
    summary["flag_wrapping_helpers"]=clean
    # v47 review lanes for UI.
    flags=summary.get("flags",[]) or []
    artifacts=summary.get("artifacts",[]) or []
    summary["sloper47_review_lanes"]={
        "promoted_flags_count":len(flags),
        "wrapper_candidates_count":len(clean),
        "priority_artifacts_count":len([a for a in artifacts if int(a.get("score",0) or 0)>=250]),
        "files_analyzed":len(reports),
        "status":"solved" if flags else ("review_candidates" if clean or artifacts else "needs_manual_work")
    }
    summary["sloper47_project_health"]={
        "warning": "" if flags or clean or artifacts else "No strong evidence produced. Try manual tools or add more files/statement context.",
        "advice": "Use Dashboard -> Evidence Timeline -> Priority Artifacts -> Wrappers. Promoted Flags are intentionally stricter than wrapper candidates.",
    }
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper47" in txt or "v47" in txt: s+=4400
        if any(k in txt for k in ["noise_filtered","time_anomaly","canvas","review","manifest"]): s+=900
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(summary.get("artifacts",[]),key=pri,reverse=True)[:3600]
    na=summary.get("sloper46_next_actions",[]) or summary.get("sloper45_next_actions",[]) or summary.get("workflow_steps",[]) or []
    lane=summary["sloper47_review_lanes"]
    if lane["status"]=="review_candidates":
        na.insert(0,{"priority":99,"step":"Review candidates before submitting.","why":"No strict promoted flag, but v47 found wrapper/artifact evidence. Avoid submitting random candidates without checking source artifact."})
    elif lane["status"]=="solved":
        na.insert(0,{"priority":99,"step":"Verify promoted flag against evidence.","why":"Open the top artifact/trace to confirm the promoted flag before submitting."})
    summary["sloper47_next_actions"]=na[:28]
    summary["workflow_steps"]=na[:28]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v47"
def sl47_project_has_fast_log(root):
    try:
        for p in (Path(root)/"files").rglob("*"):
            if p.is_file() and not sl45_is_internal_generated_file(p,root) and sl47_should_fast_log(p):
                return True
    except Exception:
        return False
    return False
def sl47_lightweight_text_report(pid, p, root, note="Context/statement file; skipped legacy brute-force."):
    p=Path(p); data=p.read_bytes()
    rel=str(p.relative_to(root)) if str(p).startswith(str(root)) else p.name
    text=data[:200000].decode("utf-8","ignore")
    report={
        "id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":rel,"kind":"text_context",
        "size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest(),"magic":data[:32].hex(),
        "flags":[],"weak_flag_candidates":[],"verified_flags":[],"verified_flags_visible":[],"strings":py_strings(data,limit=400),"outputs":[],"previews":[],
        "commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"transformations":[],"findings":[],
        "next_steps":[],"solve_trace":[{"stage":"SLOPER v47 lightweight context","detail":note,"confidence":160,"artifact":str(p),"flag":""}],
        "agent_trace":[],"answer_candidates":[],"flag_wrapping_helpers":[],"evidence_scored_candidates":[]
    }
    try: sl45_promote_answer_markers(report,text,"SLOPER v47 context marker",str(p),210)
    except Exception: pass
    return report
def sl47_fast_log_project(pid):
    root=pdir(pid); meta=jread(meta_path(pid),{})
    reports=[]
    files=[p for p in (root/"files").rglob("*") if p.is_file() and not sl45_is_internal_generated_file(p,root)]
    log_files=[p for p in files if sl47_should_fast_log(p)]
    ctx_files=[p for p in files if p not in log_files]
    total=max(1,len(files))
    progress(pid,2,"v47 fast log project mode")
    for i,p in enumerate(log_files,1):
        progress(pid,min(85,5+i*20),f"v47 fast log {p.name}")
        try:
            reports.append(sl47_fast_log_analyze_file(pid,p,root,i,total))
        except Exception as e:
            reports.append({"id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":str(p.relative_to(root)),"kind":"error","error":str(e),"flags":[],"strings":[],"outputs":[],"artifacts":[],"transformations":[],"findings":[{"score":20,"type":"v47_fast_log_error","value":str(e),"why":"Fast log project path failed."}],"next_steps":[{"priority":20,"step":"Inspect log manually; v47 fast-log failed.","why":str(e)}],"solve_trace":[],"agent_trace":[],"answer_candidates":[],"flag_wrapping_helpers":[]})
    for p in ctx_files[:6]:
        # Keep statement/context visible but avoid old heavy analyzer.
        if p.suffix.lower() in [".txt",".md",".log",".jsonl"]:
            reports.append(sl47_lightweight_text_report(pid,p,root))
        elif not any(r.get("flags") for r in reports):
            # Non-text side files are analyzed only if no log result exists.
            try:
                reports.append(_prev_analyze_file_v47(pid,p,root,1,total))
            except Exception as e:
                reports.append({"id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":str(p.relative_to(root)),"kind":"error","error":str(e),"flags":[],"strings":[],"outputs":[],"artifacts":[],"findings":[],"next_steps":[]})
    progress(pid,95,"summary")
    jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    progress(pid,100,"Done")
    with LOCK: JOBS.setdefault(pid,{})["status"]="done"
def wf_flag_has_solve_evidence(report, flag):
    low=str(flag or "").lower()
    if not low:
        return False
    support=0
    try:
        for t in report.get("solve_trace",[])[:60]:
            if low in json.dumps(t,ensure_ascii=False).lower():
                support += 2
                if support>=2: return True
        for a in report.get("artifacts",[])[:80]:
            p=Path(a.get("path",""))
            try:
                if p.exists() and p.is_file() and p.stat().st_size<350000:
                    txt=p.read_bytes()[:350000].decode("utf-8","ignore").lower()
                    if low in txt:
                        support+=2
                        if support>=2: return True
            except Exception:
                pass
        for c in report.get("answer_candidates",[])[:80]:
            if str(c.get("value","")).lower() in low or low in str(c.get("value","")).lower():
                support+=1
    except Exception:
        pass
    return support>=2
_prev_analyze_project_v47_fast_log = analyze_project
def analyze_project(pid):
    root=pdir(pid)
    if sl47_project_has_fast_log(root):
        return sl47_fast_log_project(pid)
    return _prev_analyze_project_v47_fast_log(pid)
def sl48_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl47_trace(report, "v48:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v48:"+str(stage),
            "detail":str(detail)[:1300],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl48_art(root, report, name, content, kind="sloper48_artifact", score=180, note=""):
    outdir=root/"generated"/"sloper48"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v48","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl48_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl48_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl48_bytes_to_printable(bs):
    bs=bytes(bs or b"")
    return "".join(chr(b) if 32 <= b < 127 or b in (9,10,13) else "." for b in bs)
def sl48_bits_to_bytes(bits, max_bytes=200000):
    out=bytearray()
    n=min(len(bits)//8, max_bytes)
    for i in range(n):
        try:
            out.append(int(bits[i*8:(i+1)*8],2))
        except Exception:
            break
    return bytes(out)
def sl48_promote_from_text(report, text, source, artifact=None, score=260):
    try:
        sl45_promote_answer_markers(report,text,source,artifact,score)
    except Exception:
        pass
    try:
        for f in vf_primary_flags(str(text),limit=10,scan_limit=300000):
            if f not in report.setdefault("flags",[]):
                report["flags"].append(f)
                sl48_trace(report,"strict flag",f,score,artifact,f)
    except Exception:
        pass
def sl48_image_lsb_agent(report, root, data):
    p=Path(report.get("path",""))
    if report.get("kind")!="image" and p.suffix.lower() not in [".png",".jpg",".jpeg",".bmp",".gif",".webp",".tif",".tiff"]:
        return []
    if len(data)>10_000_000:
        return []
    try:
        from PIL import Image
    except Exception:
        return []
    try:
        img=Image.open(p)
        img.load()
    except Exception as e:
        sl48_trace(report,"ImageLSB failed",str(e),0)
        return []
    # Keep bounded for performance.
    w,h=img.size
    if w*h > 2_500_000:
        sl48_trace(report,"ImageLSB skipped",f"image too large: {w}x{h}",80)
        return []
    arts=[]
    try:
        rgba=img.convert("RGBA")
        pix=list(rgba.getdata())
        channels={"r":0,"g":1,"b":2,"a":3}
        variants=[]
        for cname,idx in channels.items():
            vals=[px[idx] for px in pix]
            for bit in range(2):  # LSB and second LSB only, bounded and useful.
                bits="".join("1" if ((v>>bit)&1) else "0" for v in vals[:1_600_000])
                raw=sl48_bits_to_bytes(bits, max_bytes=200000)
                txt=sl48_bytes_to_printable(raw[:200000])
                score=sl43_text_quality(txt) if "sl43_text_quality" in globals() else 0
                if score>=80 or "ctf" in txt.lower() or "{" in txt:
                    variants.append({"channel":cname,"bit":bit,"order":"row-major","score":score,"preview":txt[:4000],"bytes_hex_head":raw[:64].hex()})
                    name=f"lsb_{cname}{bit}_row_major.txt"
                    art=sl48_art(root,report,name,txt[:200000],"sloper48_image_lsb_text",230+min(score,200),f"Image {cname} bit {bit} row-major LSB extraction.")
                    if art:
                        arts.append(art)
                        sl48_promote_from_text(report,txt,"SLOPER v48 ImageLSB",art.get("path"),260)
                # Reverse bit order per byte variant can reveal flags.
                bits_rev="".join("1" if ((v>>bit)&1) else "0" for v in reversed(vals[:1_600_000]))
                raw2=sl48_bits_to_bytes(bits_rev,max_bytes=200000)
                txt2=sl48_bytes_to_printable(raw2[:200000])
                score2=sl43_text_quality(txt2) if "sl43_text_quality" in globals() else 0
                if score2>=100 or "ctf" in txt2.lower() or "{" in txt2:
                    variants.append({"channel":cname,"bit":bit,"order":"reverse","score":score2,"preview":txt2[:4000],"bytes_hex_head":raw2[:64].hex()})
                    art=sl48_art(root,report,f"lsb_{cname}{bit}_reverse.txt",txt2[:200000],"sloper48_image_lsb_text",220+min(score2,200),f"Image {cname} bit {bit} reverse-order LSB extraction.")
                    if art:
                        arts.append(art)
                        sl48_promote_from_text(report,txt2,"SLOPER v48 ImageLSB reverse",art.get("path"),255)
        # Combined RGB LSB stream, common in CTFs.
        bits_rgb=[]
        for px in pix[:600000]:
            bits_rgb.extend(["1" if (px[0]&1) else "0","1" if (px[1]&1) else "0","1" if (px[2]&1) else "0"])
        raw=sl48_bits_to_bytes("".join(bits_rgb),max_bytes=200000)
        txt=sl48_bytes_to_printable(raw[:200000])
        score=sl43_text_quality(txt) if "sl43_text_quality" in globals() else 0
        if score>=80 or "ctf" in txt.lower() or "{" in txt:
            variants.append({"channel":"rgb","bit":0,"order":"rgb_interleaved","score":score,"preview":txt[:4000],"bytes_hex_head":raw[:64].hex()})
            art=sl48_art(root,report,"lsb_rgb_interleaved.txt",txt[:200000],"sloper48_image_lsb_text",250+min(score,200),"RGB interleaved LSB extraction.")
            if art:
                arts.append(art)
                sl48_promote_from_text(report,txt,"SLOPER v48 RGB interleaved LSB",art.get("path"),280)
        if variants:
            mart=sl48_art(root,report,"image_lsb_manifest.json",json.dumps(variants[:80],indent=2,ensure_ascii=False),"sloper48_image_lsb_manifest",280,"Manifest of useful LSB/channel text extractions.")
            if mart: arts.append(mart)
    except Exception as e:
        sl48_trace(report,"ImageLSB exception",str(e),0)
    return arts
def sl48_palette_agent(report, root, data):
    p=Path(report.get("path",""))
    if p.suffix.lower() not in [".png",".gif",".bmp"] and report.get("kind")!="image":
        return []
    try:
        from PIL import Image
    except Exception:
        return []
    try:
        img=Image.open(p)
        img.load()
    except Exception:
        return []
    arts=[]
    try:
        pal=img.getpalette()
        mode=img.mode
        obj={"mode":mode,"size":img.size,"has_palette":bool(pal),"palette_len":len(pal) if pal else 0}
        # Palette bytes sometimes directly encode text or bitstream.
        if pal:
            pb=bytes([x&255 for x in pal])
            txt=sl48_bytes_to_printable(pb)
            obj["palette_ascii_preview"]=txt[:4000]
            obj["palette_hex_head"]=pb[:128].hex()
            if sl43_text_quality(txt)>80 or "ctf" in txt.lower() or "{" in txt:
                art=sl48_art(root,report,"palette_ascii.txt",txt,"sloper48_palette_ascii",250,"Palette bytes rendered as ASCII.")
                if art:
                    arts.append(art)
                    sl48_promote_from_text(report,txt,"SLOPER v48 PaletteASCII",art.get("path"),270)
        # Index stream for P-mode images.
        if mode=="P":
            idx_bytes=bytes(list(img.getdata())[:800000])
            txt=sl48_bytes_to_printable(idx_bytes)
            obj["index_ascii_preview"]=txt[:4000]
            if sl43_text_quality(txt)>80 or "ctf" in txt.lower() or "{" in txt:
                art=sl48_art(root,report,"palette_index_ascii.txt",txt[:200000],"sloper48_palette_index_ascii",255,"Palette index values rendered as ASCII.")
                if art:
                    arts.append(art)
                    sl48_promote_from_text(report,txt,"SLOPER v48 PaletteIndex",art.get("path"),270)
        mart=sl48_art(root,report,"palette_analysis.json",json.dumps(obj,indent=2,ensure_ascii=False),"sloper48_palette_analysis",210,"Palette/index metadata and ASCII previews.")
        if mart: arts.append(mart)
    except Exception as e:
        sl48_trace(report,"Palette exception",str(e),0)
    return arts
def sl48_pcap_field_fallback_agent(report, root, data):
    p=Path(report.get("path",""))
    if p.suffix.lower() not in [".pcap",".pcapng"] and report.get("kind")!="pcap":
        return []
    if not exists("tshark"):
        return []
    fields=[
        ("dns_names",["-T","fields","-e","dns.qry.name","-e","dns.txt"]),
        ("http_fields",["-T","fields","-e","http.host","-e","http.request.uri","-e","http.cookie","-e","http.file_data"]),
        ("tcp_payloads",["-T","fields","-e","tcp.payload"]),
        ("udp_payloads",["-T","fields","-e","udp.payload"]),
        ("icmp_data",["-T","fields","-e","data.data"]),
        ("scalar_fields",["-T","fields","-e","ip.id","-e","ip.ttl","-e","ip.len","-e","tcp.seq","-e","tcp.ack","-e","tcp.window_size_value"]),
    ]
    arts=[]
    manifest={}
    for name,args in fields:
        try:
            r=run(["tshark","-r",str(p)]+args,25)
            out=r.get("out","")[:2_000_000]
            if not out.strip():
                continue
            art=sl48_art(root,report,f"pcap_{name}.txt",out,"sloper48_pcap_field_extract",230,f"tshark field extraction: {name}")
            if art: arts.append(art)
            manifest[name]={"lines":len(out.splitlines()),"chars":len(out)}
            # Decode hex payload fields.
            decoded=[]
            for tok in re.findall(r"(?:[0-9a-fA-F]{2}:?){4,}",out)[:2000]:
                hx=re.sub(r"[^0-9a-fA-F]","",tok)
                if len(hx)%2==0 and 8<=len(hx)<=20000:
                    try:
                        raw=bytes.fromhex(hx)
                        txt=raw.decode("utf-8","ignore")
                        if txt and (sl43_text_quality(txt)>70 or "ctf" in txt.lower() or "{" in txt):
                            decoded.append(txt)
                    except Exception:
                        pass
            if decoded:
                dtext="\n---DECODED---\n".join(decoded[:200])
                dart=sl48_art(root,report,f"pcap_{name}_decoded_ascii.txt",dtext,"sloper48_pcap_decoded_ascii",280,f"Decoded ASCII from hex payload field: {name}")
                if dart:
                    arts.append(dart)
                    sl48_promote_from_text(report,dtext,"SLOPER v48 PCAP decoded fields",dart.get("path"),300)
            else:
                sl48_promote_from_text(report,out,"SLOPER v48 PCAP field text",art.get("path") if art else "",230)
        except Exception as e:
            sl48_trace(report,"PCAP field failed",f"{name}: {e}",0)
    if manifest:
        mart=sl48_art(root,report,"pcap_field_extract_manifest.json",json.dumps(manifest,indent=2,ensure_ascii=False),"sloper48_pcap_manifest",260,"PCAP field extraction manifest.")
        if mart: arts.append(mart)
    return arts
def sl48_run_agents(report, root, data):
    arts=[]
    try: arts += sl48_image_lsb_agent(report,root,data)
    except Exception as e: sl48_trace(report,"ImageLSB failed",str(e),0)
    try: arts += sl48_palette_agent(report,root,data)
    except Exception as e: sl48_trace(report,"Palette failed",str(e),0)
    try: arts += sl48_pcap_field_fallback_agent(report,root,data)
    except Exception as e: sl48_trace(report,"PCAP fallback failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v48 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v48(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl48_trace(report,"previous agents failed",str(e),0)
    # If a strong flag is already found and this is a big image, skip optional LSB noise unless visual/stego hinted.
    try:
        already=bool(report.get("flags"))
        if already and report.get("kind")=="image" and not sl44_visual_hint(report):
            return arts
    except Exception:
        pass
    try:
        arts += sl48_run_agents(report,root,data) or []
    except Exception as e:
        sl48_trace(report,"v48 agents failed",str(e),0)
    return arts
_prev_project_summary_v48 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v48(reports, meta)
    # Never show more than 5 promoted flags unless they are exact strict flags from different files.
    flags=summary.get("flags",[]) or []
    clean_flags=[]; seen=set()
    for f in flags:
        ff=f.get("flag") if isinstance(f,dict) else str(f)
        body=ff[7:-1] if ff.startswith("ctf_cs{") and ff.endswith("}") else ff
        if sl42_is_bad_wrapper_body(body):
            continue
        key=ff.lower()
        if key not in seen:
            seen.add(key); clean_flags.append(f)
        if len(clean_flags)>=8:
            break
    summary["flags"]=clean_flags
    caps=summary.get("sloper47_review_lanes",{}) or {}
    caps["v48_image_lsb_artifacts"]=len([a for a in summary.get("artifacts",[]) if "sloper48_image_lsb" in a.get("kind","")])
    caps["v48_palette_artifacts"]=len([a for a in summary.get("artifacts",[]) if "sloper48_palette" in a.get("kind","")])
    caps["v48_pcap_artifacts"]=len([a for a in summary.get("artifacts",[]) if "sloper48_pcap" in a.get("kind","")])
    summary["sloper48_review_lanes"]=caps
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper48" in txt or "v48" in txt: s+=5000
        if any(k in txt for k in ["lsb","palette","pcap_field","decoded_ascii","manifest"]): s+=1100
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(summary.get("artifacts",[]),key=pri,reverse=True)[:3800]
    na=summary.get("sloper47_next_actions",[]) or summary.get("workflow_steps",[]) or []
    if caps.get("v48_image_lsb_artifacts") or caps.get("v48_palette_artifacts"):
        na.insert(0,{"priority":96,"step":"Review v48 image stego artifacts.","why":"v48 generated LSB/palette artifacts that may reveal hidden text after transformation."})
    if caps.get("v48_pcap_artifacts"):
        na.insert(0,{"priority":95,"step":"Review v48 PCAP field artifacts.","why":"v48 extracted DNS/HTTP/payload/scalar fields and decoded payload ASCII."})
    summary["sloper48_next_actions"]=na[:30]
    summary["workflow_steps"]=na[:30]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v48"
def sl49_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl48_trace(report, "v49:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v49:"+str(stage),
            "detail":str(detail)[:1400],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl49_art(root, report, name, content, kind="sloper49_artifact", score=190, note=""):
    outdir=root/"generated"/"sloper49"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v49","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl49_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl49_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl49_promote_text(report, text, source, artifact=None, score=260):
    try:
        sl45_promote_answer_markers(report,text,source,artifact,score)
    except Exception:
        pass
    try:
        for f in vf_primary_flags(str(text),limit=8,scan_limit=250000):
            if f not in report.setdefault("flags",[]):
                report["flags"].append(f)
                sl49_trace(report,"strict flag",f,score,artifact,f)
    except Exception:
        pass
def sl49_make_contact_sheet(images, labels, thumb=(240,160), cols=3):
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception:
        return None
    if not images:
        return None
    rows=(len(images)+cols-1)//cols
    label_h=26
    sheet=Image.new("RGB",(cols*thumb[0],rows*(thumb[1]+label_h)),"white")
    draw=ImageDraw.Draw(sheet)
    for idx,im in enumerate(images):
        r=idx//cols; c=idx%cols
        try:
            img=im.convert("RGB")
            img.thumbnail(thumb)
            x=c*thumb[0]+(thumb[0]-img.width)//2
            y=r*(thumb[1]+label_h)
            sheet.paste(img,(x,y))
            lab=str(labels[idx])[:42]
            draw.text((c*thumb[0]+6,y+thumb[1]+4),lab,fill=(0,0,0))
        except Exception:
            pass
    return sheet
def sl49_image_visual_review_agent(report, root, data):
    p=Path(report.get("path",""))
    if report.get("kind")!="image" and p.suffix.lower() not in [".png",".jpg",".jpeg",".bmp",".gif",".webp",".tif",".tiff"]:
        return []
    if len(data)>12_000_000:
        return []
    try:
        from PIL import Image, ImageOps, ImageEnhance, ImageFilter
    except Exception:
        return []
    try:
        img=Image.open(p)
        img.load()
    except Exception as e:
        sl49_trace(report,"VisualReview failed",str(e),0)
        return []
    w,h=img.size
    if w*h>3_000_000:
        sl49_trace(report,"VisualReview skipped",f"image too large: {w}x{h}",80)
        return []
    arts=[]
    try:
        base=img.convert("RGB")
        if max(base.size)<900:
            scale=max(2,min(5,900//max(1,max(base.size))))
            up=base.resize((base.width*scale,base.height*scale))
        else:
            up=base
        gray=ImageOps.grayscale(up)
        transforms=[]
        transforms.append(("gray",gray))
        transforms.append(("autocontrast",ImageOps.autocontrast(gray)))
        transforms.append(("invert",ImageOps.invert(gray)))
        transforms.append(("sharpen",gray.filter(ImageFilter.SHARPEN)))
        transforms.append(("edge_find",gray.filter(ImageFilter.FIND_EDGES)))
        transforms.append(("emboss",gray.filter(ImageFilter.EMBOSS)))
        transforms.append(("contrast3",ImageEnhance.Contrast(gray).enhance(3.0)))
        transforms.append(("contrast6",ImageEnhance.Contrast(gray).enhance(6.0)))
        for t in [64,96,128,160,192]:
            transforms.append((f"threshold_{t}",gray.point(lambda x,t=t:255 if x>t else 0)))
        for angle in [90,180,270]:
            transforms.append((f"rot_{angle}",gray.rotate(angle,expand=True)))
        # Crop quadrants sometimes useful for hidden side text.
        bw,bh=gray.size
        if bw>=100 and bh>=100:
            crops=[("crop_tl",(0,0,bw//2,bh//2)),("crop_tr",(bw//2,0,bw,bh//2)),("crop_bl",(0,bh//2,bw//2,bh)),("crop_br",(bw//2,bh//2,bw,bh))]
            for name,box in crops:
                transforms.append((name,ImageOps.autocontrast(gray.crop(box)).resize((bw,bh))))
        outdir=root/"generated"/"sloper49"/safe(report.get("name","file"))/"visual_review"
        outdir.mkdir(parents=True,exist_ok=True)
        saved=[]; ims=[]; labels=[]
        for name,im in transforms[:24]:
            out=outdir/(safe(name)+".png")
            try:
                im.save(out)
                art={"kind":"sloper49_visual_transform","name":out.name,"path":str(out),"url":"/api/raw?path="+str(out),"source":"CTF SLOPER v49","score":245,"note":f"Visual review transform: {name}","exists":True,"size":out.stat().st_size,"file":report.get("rel","")}
                report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art)
                saved.append((name,out)); ims.append(im); labels.append(name)
            except Exception:
                pass
        sheet=sl49_make_contact_sheet(ims,labels,thumb=(260,180),cols=3)
        if sheet:
            sp=outdir/"visual_contact_sheet.png"
            sheet.save(sp)
            art={"kind":"sloper49_visual_contact_sheet","name":sp.name,"path":str(sp),"url":"/api/raw?path="+str(sp),"source":"CTF SLOPER v49","score":360,"note":"Contact sheet of visual transforms for fast human inspection.","exists":True,"size":sp.stat().st_size,"file":report.get("rel","")}
            report.setdefault("artifacts",[]).insert(0,art); report.setdefault("transformations",[]).insert(0,art); arts.insert(0,art)
        # OCR/QR on selected best text-ish transforms only.
        hits=[]
        selected=[x for x in saved if any(k in x[0] for k in ["threshold","autocontrast","invert","edge","rot"])]
        for name,out in selected[:16]:
            try:
                if exists("zbarimg"):
                    r=run(["zbarimg","--quiet",str(out)],8)
                    txt=(r.get("out") or "").strip()
                    if txt:
                        hits.append({"tool":"zbarimg","image":name,"text":txt})
                        sl49_promote_text(report,txt,"SLOPER v49 Visual QR",str(out),310)
                if exists("tesseract"):
                    r=run(["tesseract",str(out),"stdout","--psm","6"],10)
                    txt=(r.get("out") or "").strip()
                    if txt and (sl43_text_quality(txt)>90 or "ctf" in txt.lower() or "{" in txt):
                        hits.append({"tool":"tesseract","image":name,"text":txt[:3000]})
                        sl49_promote_text(report,txt,"SLOPER v49 Visual OCR",str(out),290)
            except Exception:
                pass
        if hits:
            hart=sl49_art(root,report,"visual_ocr_qr_hits.json",json.dumps(hits,indent=2,ensure_ascii=False),"sloper49_visual_ocr_qr_hits",330,"OCR/QR hits from selected visual transforms.")
            if hart: arts.insert(0,hart)
        if arts:
            report.setdefault("next_steps",[]).insert(0,{"priority":98,"step":"Open visual_contact_sheet.png.","why":"v49 generated a single contact sheet with contrast/threshold/edge/rotation variants for fast human inspection."})
            sl49_trace(report,"VisualReview",f"{len(saved)} visual transforms and contact sheet generated",360,arts[0].get("path"))
    except Exception as e:
        sl49_trace(report,"VisualReview exception",str(e),0)
    return arts
def sl49_fast_text_decode_agent(report, root, data):
    p=Path(report.get("path",""))
    if p.suffix.lower() not in [".txt",".md",".log",".csv",".json",".dat",".enc"]:
        return []
    if len(data)>1_500_000:
        return []
    text=data.decode("utf-8","ignore")
    if not text.strip():
        return []
    # Avoid duplicating specialized fast Cardan/log modes.
    if "Cardan" in json.dumps(report.get("solve_trace",[]),ensure_ascii=False) or sl47_is_artifact_json_log(text) or sl47_is_time_log(text):
        return []
    arts=[]
    candidates=[]
    try:
        decs=sl43_decode_chain_text(text[:250000],3)
    except Exception:
        decs=[]
    for d in decs[:120]:
        t=d.get("text","")
        sc=int(d.get("score",0) or 0)
        if sc>=150 or "ctf" in t.lower() or "{" in t or re.search(r"[a-z0-9]{2,}_[a-z0-9_]{2,}",t.lower()):
            candidates.append({"method":d.get("method"),"depth":d.get("depth"),"score":sc,"text":t[:8000]})
    # Classic small extras: Caesar/ROT candidate summary without promotion spam.
    def caesar(s,shift):
        out=[]
        for ch in s:
            if "a"<=ch<="z": out.append(chr((ord(ch)-97+shift)%26+97))
            elif "A"<=ch<="Z": out.append(chr((ord(ch)-65+shift)%26+65))
            else: out.append(ch)
        return "".join(out)
    lines=[x.strip() for x in text.splitlines() if 6<=len(x.strip())<=600]
    for line in lines[:30]:
        for sh in range(1,26):
            dec=caesar(line,sh)
            sc=sl43_text_quality(dec)
            if sc>=170 or "ctf" in dec.lower() or "{" in dec:
                candidates.append({"method":f"caesar_{sh}","depth":1,"score":sc,"text":dec[:4000]})
    if candidates:
        # Dedup and cap.
        out=[]; seen=set()
        for c in sorted(candidates,key=lambda x:x.get("score",0),reverse=True):
            k=c["text"][:200]
            if k not in seen:
                seen.add(k); out.append(c)
            if len(out)>=80:
                break
        art=sl49_art(root,report,"fast_text_decode_candidates.json",json.dumps(out,indent=2,ensure_ascii=False),"sloper49_fast_text_decode",300,"Bounded decode candidates for text challenge; candidates are not blindly promoted.")
        if art:
            arts.append(art)
            for c in out[:20]:
                sl49_promote_text(report,c["text"],"SLOPER v49 FastTextDecode",art.get("path"),260)
            report.setdefault("next_steps",[]).insert(0,{"priority":94,"step":"Open fast_text_decode_candidates.json.","why":"v49 generated bounded decode candidates without running slow legacy brute-force."})
    return arts
def sl49_run_agents(report, root, data):
    arts=[]
    try: arts += sl49_image_visual_review_agent(report,root,data)
    except Exception as e: sl49_trace(report,"VisualReview failed",str(e),0)
    try: arts += sl49_fast_text_decode_agent(report,root,data)
    except Exception as e: sl49_trace(report,"FastTextDecode failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v49 = sl_run_agents
