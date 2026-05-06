# Auto-split from sloper_legacy_monolith.py lines 15936-...
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v49(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl49_trace(report,"previous agents failed",str(e),0)
    try:
        # Skip optional visual transforms when flag already found and no visual/stego hint.
        if report.get("kind")=="image" and report.get("flags") and not sl44_visual_hint(report):
            return arts
    except Exception:
        pass
    try:
        arts += sl49_run_agents(report,root,data) or []
    except Exception as e:
        sl49_trace(report,"v49 agents failed",str(e),0)
    return arts
_prev_project_summary_v49 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v49(reports, meta)
    artifacts=summary.get("artifacts",[]) or []
    flags=summary.get("flags",[]) or []
    wrappers=summary.get("flag_wrapping_helpers",[]) or []
    kinds={}
    for a in artifacts:
        kind=str(a.get("kind","unknown"))
        family="other"
        low=kind.lower()+" "+a.get("name","").lower()
        if "visual" in low or "image" in low or "lsb" in low or "palette" in low: family="image/stego"
        elif "pcap" in low or "dns" in low or "tcp" in low or "http" in low: family="pcap/network"
        elif "cardan" in low or "sha256" in low or "crypto" in low or "decode" in low: family="crypto/text"
        elif "tar" in low or "zip" in low or "archive" in low or "embedded" in low: family="archive"
        elif "reverse" in low or "byte_array" in low or "cmp" in low: family="reversing"
        elif "time" in low or "artifact_log" in low or "canvas" in low: family="misc/log"
        kinds[family]=kinds.get(family,0)+1
    status="solved" if flags else ("review_candidates" if wrappers or artifacts else "needs_manual_work")
    summary["sloper49_project_brief"]={
        "status":status,
        "title":meta.get("title",""),
        "category":meta.get("category",""),
        "promoted_flags":len(flags),
        "wrapper_candidates":len(wrappers),
        "priority_artifacts":len([a for a in artifacts if int(a.get("score",0) or 0)>=250]),
        "artifact_families":kinds,
        "inspect_first":"Promoted Flags" if flags else ("Priority Artifacts" if artifacts else "Manual Tools"),
        "warning":"" if flags else "No strict flag was promoted. Treat wrappers as candidates and verify source artifacts before submitting."
    }
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper49" in txt or "v49" in txt: s+=5600
        if "contact_sheet" in txt or "visual_ocr_qr" in txt: s+=1600
        if "fast_text_decode" in txt: s+=1100
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(artifacts,key=pri,reverse=True)[:4000]
    lane=summary.get("sloper48_review_lanes",{}) or summary.get("sloper47_review_lanes",{}) or {}
    lane["v49_visual_artifacts"]=len([a for a in artifacts if "sloper49_visual" in a.get("kind","")])
    lane["v49_text_decode_artifacts"]=len([a for a in artifacts if "sloper49_fast_text" in a.get("kind","")])
    summary["sloper49_review_lanes"]=lane
    na=summary.get("sloper48_next_actions",[]) or summary.get("workflow_steps",[]) or []
    if lane.get("v49_visual_artifacts"):
        na.insert(0,{"priority":99,"step":"Open visual_contact_sheet.png first.","why":"v49 assembled visual transforms into one contact sheet for quick human inspection."})
    if lane.get("v49_text_decode_artifacts"):
        na.insert(0,{"priority":95,"step":"Open fast_text_decode_candidates.json.","why":"v49 generated bounded text decode candidates without promoting weak guesses."})
    summary["sloper49_next_actions"]=na[:32]
    summary["workflow_steps"]=na[:32]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v49"
def sl50_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl49_trace(report, "v50:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v50:"+str(stage),
            "detail":str(detail)[:1500],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl50_art(root, report, name, content, kind="sloper50_artifact", score=200, note=""):
    outdir=root/"generated"/"sloper50"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v50","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl50_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl50_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl50_magic_kind(bs):
    bs=bytes(bs or b"")
    heads=[
        (b"\x7fELF","ELF executable/library"),
        (b"MZ","PE/MZ executable"),
        (b"PK\x03\x04","ZIP/APK/DOCX/JAR archive"),
        (b"\x1f\x8b\x08","Gzip stream"),
        (b"BZh","BZip2 stream"),
        (b"\xfd7zXZ\x00","XZ stream"),
        (b"\x89PNG\r\n\x1a\n","PNG image"),
        (b"\xff\xd8\xff","JPEG image"),
        (b"%PDF","PDF document"),
        (b"SQLite format 3\x00","SQLite database"),
        (b"Rar!\x1a\x07","RAR archive"),
        (b"7z\xbc\xaf\x27\x1c","7z archive"),
    ]
    out=[]
    for sig,name in heads:
        if bs.startswith(sig):
            out.append(name)
    if len(bs)>262 and bs[257:262]==b"ustar":
        out.append("TAR archive")
    return out
def sl50_text_score(bs):
    bs=bytes(bs or b"")
    if not bs:
        return 0
    sample=bs[:200000]
    printable=sum(1 for b in sample if 32<=b<127 or b in (9,10,13))
    ratio=printable/max(1,len(sample))
    txt=sample.decode("utf-8","ignore").lower()
    score=int(ratio*100)
    for w in ["ctf_cs{","flag","secret","password","raktas","slapta","cyber","sprint","http","https"]:
        if w in txt:
            score+=80
    if re.search(r"[a-z0-9]{2,}_[a-z0-9_]{2,}",txt):
        score+=60
    if "{" in txt and "}" in txt:
        score+=50
    return score
def sl50_rol(b,n):
    return ((b<<n)&255)|(b>>(8-n))
def sl50_ror(b,n):
    return (b>>n)|((b<<(8-n))&255)
def sl50_extract_candidate_keys(report):
    blob=""
    try:
        blob += ux_statement_text(report)+"\n"
    except Exception:
        pass
    try:
        blob += "\n".join(report.get("strings",[])[:80])+"\n"
    except Exception:
        pass
    keys=set([0x00,0x01,0x02,0x03,0x10,0x13,0x20,0x21,0x30,0x31,0x32,0x33,0x37,0x42,0x52,0x55,0x5a,0x66,0x69,0x7f,0x80,0x90,0xaa,0xcc,0xff])
    for m in re.finditer(r"0x([0-9a-fA-F]{1,2})",blob):
        try: keys.add(int(m.group(1),16)&255)
        except Exception: pass
    for m in re.finditer(r"(?i)(?:xor|key|raktas|shift|add|sub)\D{0,20}(\d{1,3})",blob):
        try:
            v=int(m.group(1))
            if 0<=v<=255: keys.add(v)
        except Exception:
            pass
    for m in re.finditer(r"(?i)(?:key|raktas|password|pass)\s*[:=]\s*([A-Za-z0-9_@#.$+\-]{1,24})",blob):
        s=m.group(1).encode("utf-8","ignore")
        for b in s[:24]:
            keys.add(b)
    return sorted(keys)
def sl50_should_deep_transform(report, data):
    data=bytes(data or b"")
    if not data or len(data)>4_000_000:
        return False
    p=Path(report.get("path",""))
    kind=report.get("kind","")
    hint=(ux_statement_text(report)+" "+str(report.get("name",""))).lower()
    if any(k in hint for k in ["xor","add","sub","shift","rotate","rol","ror","packed","encoded","užkodu","uzkodu","reverse","reversing","binary","elf","exe"]):
        return True
    if kind in ["binary","generic","archive","python_bytecode"] or p.suffix.lower() in ["",".bin",".dat",".enc",".raw",".elf",".exe",".so",".dll",".packed"]:
        return True
    # For images/pcap, byte transforms are too noisy unless hinted.
    return False
def sl50_transform_candidates(report, data):
    data=bytes(data or b"")
    keys=sl50_extract_candidate_keys(report)
    hint=(ux_statement_text(report)+" "+str(report.get("name",""))).lower()
    brute_all = len(data)<=220000 or any(k in hint for k in ["xor","brute","key","raktas","encoded","užkodu","uzkodu"])
    if brute_all:
        for k in range(256):
            if k not in keys:
                keys.append(k)
    transforms=[]
    def add(name, bs, method, key=None, score_bonus=0):
        bs=bytes(bs)
        magic=sl50_magic_kind(bs)
        text_score=sl50_text_score(bs)
        strict=False
        try:
            strict=bool(vf_primary_flags(bs[:300000].decode("utf-8","ignore"),limit=2,scan_limit=300000))
        except Exception:
            pass
        score=text_score+score_bonus+(220 if magic else 0)+(300 if strict else 0)
        if magic or strict or score>=135:
            transforms.append({"name":name,"method":method,"key":key,"score":score,"magic":magic,"text_score":text_score,"data":bs})
    # Global transforms.
    add("reverse.bin", data[::-1], "reverse", None, 10)
    add("not.bin", bytes((~b)&255 for b in data), "not", None, 20)
    # Rotate bits.
    for n in [1,2,3,4,5,6,7]:
        add(f"rol{n}.bin", bytes(sl50_rol(b,n) for b in data), "rol", n, 25)
        add(f"ror{n}.bin", bytes(sl50_ror(b,n) for b in data), "ror", n, 25)
    # Single byte key transforms.
    for k in keys[:256]:
        if k==0:
            continue
        add(f"xor_{k:02x}.bin", bytes(b^k for b in data), "xor", k, 35)
        add(f"add_{k:02x}.bin", bytes((b+k)&255 for b in data), "add", k, 20)
        add(f"sub_{k:02x}.bin", bytes((b-k)&255 for b in data), "sub", k, 20)
    # Rolling repeating key from obvious words.
    words=[]
    blob=(ux_statement_text(report)+" "+" ".join(report.get("strings",[])[:30])).lower()
    for w in re.findall(r"[a-zA-Z0-9_]{3,24}",blob):
        if w not in words and any(c.isalpha() for c in w):
            words.append(w)
    for w in (["ctf","cyber","sprint","secret","password","raktas","slapta"]+words)[:28]:
        kb=w.encode("utf-8","ignore")
        if not kb: continue
        out=bytes(data[i]^kb[i%len(kb)] for i in range(len(data)))
        add(f"xor_key_{safe(w)[:20]}.bin", out, "xor_repeating", w, 45)
    # Dedup by hash, keep strongest.
    out=[]; seen=set()
    for t in sorted(transforms,key=lambda x:x["score"],reverse=True):
        h=hashlib.sha256(t["data"][:500000]).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        out.append(t)
        if len(out)>=48:
            break
    return out
def sl50_child_analysis(root, parent_report, t, child_path):
    bs=t["data"]
    txt=bs[:500000].decode("utf-8","ignore")
    child={
        "name":Path(child_path).name,
        "path":str(child_path),
        "method":t.get("method"),
        "key":t.get("key"),
        "score":t.get("score"),
        "magic":t.get("magic",[]),
        "text_score":t.get("text_score",0),
        "flags":[],
        "strings":[],
        "next_actions":[],
        "artifacts":[],
    }
    try:
        child["strings"]=py_strings(bs,limit=300)
    except Exception:
        child["strings"]=[]
    try:
        child["flags"]=vf_primary_flags(txt,limit=10,scan_limit=500000)
        for f in child["flags"]:
            if f not in parent_report.setdefault("flags",[]):
                parent_report["flags"].append(f)
    except Exception:
        pass
    # Archive/image/document magic gets pushed to autopass folder for manual + future analysis.
    if t.get("magic"):
        child["next_actions"].append("Open/download transformed child file. Magic detected after transformation: "+", ".join(t.get("magic",[])))
        parent_report.setdefault("intermediate_files",[]).append({"path":str(child_path),"name":Path(child_path).name,"source":"SLOPER v50 transformed child","magic":t.get("magic",[]),"score":t.get("score",0)})
    # Run selected downstream local helpers on transformed bytes, bounded.
    try:
        if len(bs)<3_000_000:
            sf_embedded_compression_agent(parent_report,root,bs)
    except Exception:
        pass
    try:
        if t.get("magic") and any("ZIP" in x or "Gzip" in x or "BZip2" in x for x in t.get("magic",[])):
            sl45_chain_agent(parent_report,root,bs)
    except Exception:
        pass
    try:
        # Reversing helper on transformed byte arrays: useful if transform reveals readable constants.
        if len(bs)<2_000_000 and (t.get("magic") or t.get("text_score",0)>100):
            fake=dict(parent_report)
            fake["name"]=Path(child_path).name
            fake["path"]=str(child_path)
            fake["kind"]="binary" if any("ELF" in x or "PE" in x for x in t.get("magic",[])) else "generic"
            sl44_byte_array_combo_agent(fake,root,bs)
            # Copy only artifacts and flags back.
            for a in fake.get("artifacts",[]):
                if a not in parent_report.setdefault("artifacts",[]):
                    parent_report["artifacts"].append(a)
            for f in fake.get("flags",[]):
                if f not in parent_report.setdefault("flags",[]):
                    parent_report["flags"].append(f)
    except Exception:
        pass
    return child
def sl50_deep_transform_agent(report, root, data):
    if not sl50_should_deep_transform(report,data):
        return []
    arts=[]
    try:
        candidates=sl50_transform_candidates(report,data)
    except Exception as e:
        sl50_trace(report,"Transform candidates failed",str(e),0)
        return []
    if not candidates:
        return []
    outdir=root/"generated"/"sloper50"/safe(report.get("name","file"))/"transformed_children"
    outdir.mkdir(parents=True,exist_ok=True)
    manifest=[]
    for t in candidates[:32]:
        try:
            fname=safe(f"{t['score']:04d}_{t['name']}")
            p=outdir/fname
            p.write_bytes(t["data"])
            art={"kind":"sloper50_transformed_child","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v50","score":int(t["score"]),"note":f"Transformed child via {t.get('method')} key={t.get('key')} magic={','.join(t.get('magic',[])) or 'none'}","exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
            report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art)
            child=sl50_child_analysis(root,report,t,p)
            manifest.append({k:v for k,v in child.items() if k!="strings"})
        except Exception as e:
            sl50_trace(report,"Transform save/analyze failed",str(e),0)
    if manifest:
        mart=sl50_art(root,report,"transform_graph.json",json.dumps(manifest,indent=2,ensure_ascii=False),"sloper50_transform_graph",420,"Transformation graph: generated child files and downstream analysis results.")
        if mart:
            arts.insert(0,mart)
        report.setdefault("next_steps",[]).insert(0,{"priority":99,"step":"Open transform_graph.json and transformed_children/.","why":"v50 generated transformed child files and analyzed them downstream. Check children with magic/flags/high scores first."})
        sl50_trace(report,"DeepTransform",f"{len(manifest)} transformed children generated/analyzed",420,mart.get("path") if mart else "")
    return arts
def sl50_run_agents(report, root, data):
    arts=[]
    try:
        arts += sl50_deep_transform_agent(report,root,data)
    except Exception as e:
        sl50_trace(report,"DeepTransform failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v50 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v50(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl50_trace(report,"previous agents failed",str(e),0)
    try:
        arts += sl50_run_agents(report,root,data) or []
    except Exception as e:
        sl50_trace(report,"v50 agents failed",str(e),0)
    return arts
_prev_project_summary_v50 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v50(reports, meta)
    artifacts=summary.get("artifacts",[]) or []
    lane=summary.get("sloper49_review_lanes",{}) or summary.get("sloper48_review_lanes",{}) or {}
    lane["v50_transformed_children"]=len([a for a in artifacts if "sloper50_transformed_child" in a.get("kind","")])
    lane["v50_transform_graphs"]=len([a for a in artifacts if "transform_graph" in a.get("name","")])
    summary["sloper50_review_lanes"]=lane
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper50" in txt or "v50" in txt: s+=6500
        if "transform_graph" in txt: s+=1800
        if "transformed_child" in txt: s+=1300
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(artifacts,key=pri,reverse=True)[:4500]
    brief=summary.get("sloper49_project_brief",{}) or {}
    brief["v50_transformation_pipeline"]="active" if lane.get("v50_transformed_children") else "no transformed children generated"
    brief["inspect_first"]="transform_graph.json" if lane.get("v50_transform_graphs") else brief.get("inspect_first","Priority Artifacts")
    summary["sloper50_project_brief"]=brief
    na=summary.get("sloper49_next_actions",[]) or summary.get("workflow_steps",[]) or []
    if lane.get("v50_transform_graphs"):
        na.insert(0,{"priority":100,"step":"Open transform_graph.json first.","why":"v50 generated transformed child files and ran downstream analysis on them. This is the main multi-step solving path."})
    summary["sloper50_next_actions"]=na[:34]
    summary["workflow_steps"]=na[:34]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v50"
def sl50_child_analysis(root, parent_report, t, child_path):
    bs=t["data"]
    txt=bs[:500000].decode("utf-8","ignore")
    child={
        "name":Path(child_path).name,
        "path":str(child_path),
        "method":t.get("method"),
        "key":t.get("key"),
        "score":t.get("score"),
        "magic":t.get("magic",[]),
        "text_score":t.get("text_score",0),
        "flags":[],
        "strings":[],
        "next_actions":[],
        "artifacts":[],
    }
    try:
        child["strings"]=py_strings(bs,limit=220)
    except Exception:
        child["strings"]=[]
    try:
        child["flags"]=vf_primary_flags(txt,limit=10,scan_limit=500000)
        for f in child["flags"]:
            if f not in parent_report.setdefault("flags",[]):
                parent_report["flags"].append(f)
    except Exception:
        pass
    magic=t.get("magic",[]) or []
    magic_s=" ".join(magic)
    if magic:
        child["next_actions"].append("Open/download transformed child file. Magic detected after transformation: "+", ".join(magic))
        parent_report.setdefault("intermediate_files",[]).append({"path":str(child_path),"name":Path(child_path).name,"source":"SLOPER v50 transformed child","magic":magic,"score":t.get("score",0)})
    # Only expensive archive/compression follow-up when magic says it is likely useful.
    try:
        if len(bs)<3_000_000 and any(k in magic_s for k in ["ZIP","Gzip","BZip2","XZ","TAR","PNG","JPEG","PDF"]):
            sf_embedded_compression_agent(parent_report,root,bs)
    except Exception:
        pass
    try:
        if any(k in magic_s for k in ["ZIP","Gzip","BZip2","XZ","TAR"]):
            sl45_chain_agent(parent_report,root,bs)
    except Exception:
        pass
    # Reversing follow-up only for strong executable magic or very high text score.
    try:
        if len(bs)<1_500_000 and (any(k in magic_s for k in ["ELF","PE/MZ"]) or t.get("text_score",0)>170 or child["flags"]):
            fake=dict(parent_report)
            fake["name"]=Path(child_path).name
            fake["path"]=str(child_path)
            fake["kind"]="binary" if any(k in magic_s for k in ["ELF","PE/MZ"]) else "generic"
            # Byte-array combo is bounded; still, do it only for highly relevant transformed children.
            sl44_byte_array_combo_agent(fake,root,bs)
            for a in fake.get("artifacts",[])[:20]:
                if a not in parent_report.setdefault("artifacts",[]):
                    parent_report["artifacts"].append(a)
            for f in fake.get("flags",[]):
                if f not in parent_report.setdefault("flags",[]):
                    parent_report["flags"].append(f)
    except Exception:
        pass
    return child
def sl50_deep_transform_agent(report, root, data):
    if not sl50_should_deep_transform(report,data):
        return []
    arts=[]
    try:
        candidates=sl50_transform_candidates(report,data)
    except Exception as e:
        sl50_trace(report,"Transform candidates failed",str(e),0)
        return []
    if not candidates:
        return []
    outdir=root/"generated"/"sloper50"/safe(report.get("name","file"))/"transformed_children"
    outdir.mkdir(parents=True,exist_ok=True)
    manifest=[]
    # Save/analyze fewer by default; still enough for useful transform chains.
    selected=candidates[:18]
    for t in selected:
        try:
            fname=safe(f"{t['score']:04d}_{t['name']}")
            p=outdir/fname
            p.write_bytes(t["data"])
            art={"kind":"sloper50_transformed_child","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v50","score":int(t["score"]),"note":f"Transformed child via {t.get('method')} key={t.get('key')} magic={','.join(t.get('magic',[])) or 'none'}","exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
            report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art)
            # Analyze all magic/flag-like children, but keep nonmagic low-score children lightweight.
            child=sl50_child_analysis(root,report,t,p)
            manifest.append({k:v for k,v in child.items() if k!="strings"})
        except Exception as e:
            sl50_trace(report,"Transform save/analyze failed",str(e),0)
    if manifest:
        mart=sl50_art(root,report,"transform_graph.json",json.dumps(manifest,indent=2,ensure_ascii=False),"sloper50_transform_graph",420,"Transformation graph: generated child files and downstream analysis results.")
        if mart:
            arts.insert(0,mart)
        report.setdefault("next_steps",[]).insert(0,{"priority":99,"step":"Open transform_graph.json and transformed_children/.","why":"v50 generated transformed child files and analyzed them downstream. Check children with magic/flags/high scores first."})
        sl50_trace(report,"DeepTransform",f"{len(manifest)} transformed children generated/analyzed",420,mart.get("path") if mart else "")
    return arts
def sl50_child_analysis(root, parent_report, t, child_path):
    bs=t["data"]
    txt=bs[:500000].decode("utf-8","ignore")
    child={
        "name":Path(child_path).name,
        "path":str(child_path),
        "method":t.get("method"),
        "key":t.get("key"),
        "score":t.get("score"),
        "magic":t.get("magic",[]),
        "text_score":t.get("text_score",0),
        "flags":[],
        "strings":[],
        "next_actions":[],
        "artifacts":[],
    }
    try:
        child["strings"]=py_strings(bs,limit=180)
    except Exception:
        child["strings"]=[]
    try:
        child["flags"]=vf_primary_flags(txt,limit=10,scan_limit=500000)
        for f in child["flags"]:
            if f not in parent_report.setdefault("flags",[]):
                parent_report["flags"].append(f)
    except Exception:
        pass
    magic=t.get("magic",[]) or []
    magic_s=" ".join(magic)
    if magic:
        child["next_actions"].append("Open/download transformed child file. Magic detected after transformation: "+", ".join(magic))
        parent_report.setdefault("intermediate_files",[]).append({"path":str(child_path),"name":Path(child_path).name,"source":"SLOPER v50 transformed child","magic":magic,"score":t.get("score",0)})
    # Archive/compression follow-up only when useful.
    try:
        if len(bs)<3_000_000 and any(k in magic_s for k in ["ZIP","Gzip","BZip2","XZ","TAR","PNG","JPEG","PDF"]):
            sf_embedded_compression_agent(parent_report,root,bs)
    except Exception:
        pass
    try:
        if any(k in magic_s for k in ["ZIP","Gzip","BZip2","XZ","TAR"]):
            sl45_chain_agent(parent_report,root,bs)
    except Exception:
        pass
    # Expensive reverse byte-array follow-up ONLY for executable magic or an already strict flag.
    try:
        if len(bs)<1_500_000 and (any(k in magic_s for k in ["ELF","PE/MZ"]) or child["flags"]):
            fake=dict(parent_report)
            fake["name"]=Path(child_path).name
            fake["path"]=str(child_path)
            fake["kind"]="binary" if any(k in magic_s for k in ["ELF","PE/MZ"]) else "generic"
            sl44_byte_array_combo_agent(fake,root,bs)
            for a in fake.get("artifacts",[])[:8]:
                if a not in parent_report.setdefault("artifacts",[]):
                    parent_report["artifacts"].append(a)
            for f in fake.get("flags",[]):
                if f not in parent_report.setdefault("flags",[]):
                    parent_report["flags"].append(f)
    except Exception:
        pass
    return child
def sl51_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl50_trace(report, "v51:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v51:"+str(stage),
            "detail":str(detail)[:1600],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl51_art(root, report, name, content, kind="sloper51_artifact", score=210, note=""):
    outdir=root/"generated"/"sloper51"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v51","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl51_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl51_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl51_promote_text(report, text, source, artifact=None, score=270):
    try: sl45_promote_answer_markers(report,text,source,artifact,score)
    except Exception: pass
    try:
        for f in vf_primary_flags(str(text),limit=8,scan_limit=300000):
            if f not in report.setdefault("flags",[]):
                report["flags"].append(f)
                sl51_trace(report,"strict flag",f,score,artifact,f)
    except Exception:
        pass
def sl51_pyc_backdoor_agent(report, root, data):
    p=Path(report.get("path",""))
    if p.suffix.lower()!=".pyc" and b"SecureAuth" not in data[:200000]:
        return []
    arts=[]
    strings=[]
    try:
        strings=py_strings(data,limit=2000)
    except Exception:
        strings=[]
    decoded=[]
    import base64 as _b64
    for s in strings:
        for tok in re.findall(r"[A-Za-z0-9_+/=-]{8,}",s):
            if len(tok)>300:
                continue
            for fn in ["b64","urlsafe"]:
                for pad in ["","=","==","==="]:
                    try:
                        raw = (_b64.urlsafe_b64decode if fn=="urlsafe" else _b64.b64decode)(tok+pad)
                        txt=raw.decode("utf-8","ignore")
                        if txt and sum(32<=ord(c)<127 for c in txt)/max(1,len(txt))>0.75:
                            if txt not in [x.get("text") for x in decoded]:
                                decoded.append({"token":tok,"encoding":fn,"text":txt})
                    except Exception:
                        pass
    blob="\n".join(strings)+"\n"+"\n".join(x["text"] for x in decoded)
    findings={"decoded_constants":decoded[:120],"interesting_strings":[],"cwe_candidates":[],"wrapper_candidates":[]}
    for s in strings:
        low=s.lower()
        if any(k in low for k in ["secret","token","back","admin","password","jwt","hmac","csrf","session","sk_live","cwe"]):
            findings["interesting_strings"].append(s)
    # PYC backdoor tasks often ask phrase+CWE. Hardcoded secret/backdoor is usually CWE-798/321.
    phrases=[]
    for x in decoded:
        t=x["text"].strip()
        if re.search(r"(b4ck|back|d33t|final|token|recovery)",t,re.I):
            phrases.append(t)
    for s in strings:
        if re.search(r"(b4ck|back|d33t|final)",s,re.I):
            phrases.append(s.strip())
    phrases=list(dict.fromkeys(phrases))[:20]
    cwes=[
        ("CWE-798","Use of Hard-coded Credentials / hardcoded backdoor token"),
        ("CWE-321","Use of Hard-coded Cryptographic Key"),
        ("CWE-259","Use of Hard-coded Password"),
        ("CWE-287","Improper Authentication"),
    ]
    findings["cwe_candidates"]=[{"cwe":c,"why":w} for c,w in cwes]
    for ph in phrases:
        clean=re.sub(r"[^A-Za-z0-9_+\-]", "", ph)
        if not clean:
            continue
        for cwe,why in cwes[:3]:
            flag=f"ctf_cs{{{clean}+{cwe}}}"
            findings["wrapper_candidates"].append({"phrase":clean,"cwe":cwe,"suggested_flag":flag,"why":why})
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":f"{clean}+{cwe}","suggested_flag":flag,"source":"SLOPER v51 PYC Backdoor","score":340 if cwe=="CWE-798" else 300,"why":why})
    art=sl51_art(root,report,"pyc_backdoor_analysis.json",json.dumps(findings,indent=2,ensure_ascii=False),"sloper51_pyc_backdoor_analysis",360,"PYC constants/base64/CWE candidates for backdoor task.")
    if art: arts.append(art)
    if findings["wrapper_candidates"]:
        report.setdefault("next_steps",[]).insert(0,{"priority":98,"step":"Review pyc_backdoor_analysis.json.","why":"v51 decoded PYC constants and generated phrase+CWE wrapper candidates. CWE-798 is usually strongest for hardcoded backdoor credentials."})
        sl51_trace(report,"PYCBackdoor",f"{len(findings['wrapper_candidates'])} phrase+CWE wrappers generated",360,art.get("path") if art else "")
    return arts
def sl51_zip_path_agent(report, root, data):
    import zipfile as _zipfile, io as _io
    p=Path(report.get("path",""))
    if not _zipfile.is_zipfile(_io.BytesIO(data)):
        return []
    arts=[]
    seen_hash=set()
    nodes=[]
    phrases=[]
    def rec(blob, depth=0, prefix="root", limit=32):
        if depth>limit:
            nodes.append({"depth":depth,"prefix":prefix,"stop":"depth limit"})
            return
        h=hashlib.sha256(blob[:1000000]).hexdigest()
        if h in seen_hash and depth>0:
            nodes.append({"depth":depth,"prefix":prefix,"stop":"repeated zip hash"})
            return
        seen_hash.add(h)
        bio=_io.BytesIO(blob)
        if not _zipfile.is_zipfile(bio):
            return
        try:
            bio.seek(0)
            with _zipfile.ZipFile(bio) as z:
                nodes.append({"depth":depth,"prefix":prefix,"comment":z.comment.decode("utf-8","ignore"),"names":z.namelist()[:20]})
                for n in z.namelist():
                    base=n.strip("/").split("/")[-1]
                    # path names often are the phrase
                    for part in re.split(r"[\\/]+",n):
                        part=part.strip()
                        if len(part)>=12 and not part.lower().endswith(".zip"):
                            phrases.append(part)
                    try:
                        raw=z.read(n)
                        if len(raw)<5_000_000 and _zipfile.is_zipfile(_io.BytesIO(raw)):
                            rec(raw,depth+1,prefix+"::"+base,limit)
                        else:
                            txt=raw[:200000].decode("utf-8","ignore")
                            sl51_promote_text(report,txt,"SLOPER v51 recursive ZIP child",None,260)
                    except Exception as e:
                        nodes.append({"depth":depth,"name":n,"error":str(e)})
        except Exception as e:
            nodes.append({"depth":depth,"prefix":prefix,"zip_error":str(e)})
    rec(data)
    # Normalize long path phrase to likely flag body.
    phrase_candidates=[]
    for ph in phrases:
        clean=ph.strip()
        if len(clean)>200:
            continue
        body=re.sub(r"[^A-Za-z0-9]+","_",clean).strip("_").lower()
        if 6<=len(body)<=180 and not sl42_is_bad_wrapper_body(body):
            flag=f"ctf_cs{{{body}}}"
            phrase_candidates.append({"phrase":clean,"body":body,"suggested_flag":flag})
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":body,"suggested_flag":flag,"source":"SLOPER v51 recursive ZIP path","score":310,"why":"Long nested ZIP path/folder name looks like the hidden phrase."})
    manifest={"nodes":nodes[:200],"phrase_candidates":phrase_candidates[:40],"unique_zip_hashes":len(seen_hash)}
    art=sl51_art(root,report,"recursive_zip_path_analysis.json",json.dumps(manifest,indent=2,ensure_ascii=False),"sloper51_recursive_zip_path_analysis",340,"Recursive ZIP/path-name phrase analysis.")
    if art: arts.append(art)
    if phrase_candidates:
        report.setdefault("next_steps",[]).insert(0,{"priority":96,"step":"Review recursive_zip_path_analysis.json.","why":"v51 found long repeated path names in nested ZIPs; these often are the hidden phrase."})
        sl51_trace(report,"RecursiveZipPath",f"{len(phrase_candidates)} path phrase wrappers generated",340,art.get("path"))
    return arts
def sl51_parse_pcap_rawip(data):
    if len(data)<24:
        return []
    magic=data[:4]
    if magic==b"\xd4\xc3\xb2\xa1": endian="<"
    elif magic==b"\xa1\xb2\xc3\xd4": endian=">"
    else: return []
    off=24
    rows=[]
    idx=0
    while off+16<=len(data) and idx<50000:
        try:
            ts,us,inc,orig=struct.unpack(endian+"IIII",data[off:off+16]); off+=16
            pkt=data[off:off+inc]; off+=inc; idx+=1
            if len(pkt)<20: continue
            vihl=pkt[0]; ver=vihl>>4; ihl=(vihl&15)*4
            if ver!=4 or ihl<20 or len(pkt)<ihl: continue
            total=struct.unpack("!H",pkt[2:4])[0]
            ipid=struct.unpack("!H",pkt[4:6])[0]
            ttl=pkt[8]; proto=pkt[9]
            src=".".join(map(str,pkt[12:16])); dst=".".join(map(str,pkt[16:20]))
            payload=pkt[ihl:min(total,len(pkt))]
            rows.append({"idx":idx,"ts":ts,"us":us,"len":total,"ipid":ipid,"ttl":ttl,"proto":proto,"src":src,"dst":dst,"payload_hex":payload.hex(),"payload":payload})
        except Exception:
            break
    return rows
def sl51_pcap_pure_agent(report, root, data):
    p=Path(report.get("path",""))
    if p.suffix.lower() not in [".pcap",".pcapng"] and report.get("kind")!="pcap":
        return []
    rows=sl51_parse_pcap_rawip(data)
    if not rows:
        return []
    arts=[]
    import collections as _collections
    summary={
        "packet_count":len(rows),
        "proto_counts":dict(_collections.Counter(r["proto"] for r in rows)),
        "ttl_counts":dict(_collections.Counter(r["ttl"] for r in rows)),
        "flow_counts":{str(k):v for k,v in _collections.Counter((r["src"],r["dst"],r["proto"]) for r in rows).most_common(20)},
    }
    candidates=[]
    # Extract field sequences as ASCII/diffs/bits.
    fields={
        "ttl":[r["ttl"] for r in rows],
        "src_last":[int(r["src"].split(".")[-1]) for r in rows],
        "dst_last":[int(r["dst"].split(".")[-1]) for r in rows],
        "usec_low":[r["us"]&255 for r in rows],
        "payload0":[r["payload"][0] if r["payload"] else 0 for r in rows],
        "proto":[r["proto"] for r in rows],
    }
    for name,vals in fields.items():
        for variant,arr in [("raw",vals),("diff",[(vals[i]-vals[i-1])&255 for i in range(1,len(vals))]),("mod95",[(v%95)+32 for v in vals])]:
            txt="".join(chr(x) if 32<=x<127 else "." for x in arr[:5000])
            if sl43_text_quality(txt)>80 or any(k in txt.lower() for k in ["ctf","flag","secret","hidden","cyber","{"]):
                candidates.append({"field":name,"variant":variant,"preview":txt[:2000],"score":sl43_text_quality(txt)})
    # Payload hex decode chunks.
    decoded_payloads=[]
    for r in rows[:5000]:
        raw=r["payload"]
        if not raw: continue
        txt=raw.decode("utf-8","ignore")
        if txt and (sl43_text_quality(txt)>60 or any(k in txt.lower() for k in ["ctf","flag","secret","internal","service","{"])):
            decoded_payloads.append({"idx":r["idx"],"proto":r["proto"],"src":r["src"],"dst":r["dst"],"text":txt[:500]})
            sl51_promote_text(report,txt,"SLOPER v51 PCAP payload",None,260)
    # ICMP last-byte channel and TCP ports.
    icmp=[r for r in rows if r["proto"]==1]
    if icmp:
        last_bytes=[r["payload"][-1] for r in icmp if r["payload"]]
        txt="".join(chr(x) if 32<=x<127 else "." for x in last_bytes)
        candidates.append({"field":"icmp_payload_last_byte","variant":"ascii","preview":txt,"score":sl43_text_quality(txt)})
        sl51_promote_text(report,txt,"SLOPER v51 ICMP last-byte channel",None,280)
    tcp=[r for r in rows if r["proto"]==6 and len(r["payload"])>=4]
    if tcp:
        srcports=[struct.unpack("!H",r["payload"][:2])[0] for r in tcp]
        dstports=[struct.unpack("!H",r["payload"][2:4])[0] for r in tcp]
        for name,vals in [("tcp_srcport_low", [x&255 for x in srcports]),("tcp_dstport_low",[x&255 for x in dstports])]:
            txt="".join(chr(x) if 32<=x<127 else "." for x in vals)
            candidates.append({"field":name,"variant":"ascii","preview":txt[:1000],"score":sl43_text_quality(txt)})
            sl51_promote_text(report,txt,"SLOPER v51 TCP port channel",None,250)
    obj={"summary":summary,"field_candidates":candidates[:120],"decoded_payloads":decoded_payloads[:200]}
    art=sl51_art(root,report,"pure_pcap_covert_analysis.json",json.dumps(obj,indent=2,ensure_ascii=False),"sloper51_pure_pcap_covert_analysis",360,"Pure-Python PCAP covert-field extraction without tshark.")
    if art: arts.append(art)
    report.setdefault("next_steps",[]).insert(0,{"priority":97,"step":"Review pure_pcap_covert_analysis.json.","why":"v51 parsed PCAP without tshark and extracted IP/ICMP/TCP/UDP covert-field candidates."})
    sl51_trace(report,"PurePCAP",f"{len(rows)} packets parsed; {len(candidates)} field candidates",360,art.get("path") if art else "")
    return arts
def sl51_png_advanced_agent(report, root, data):
    p=Path(report.get("path",""))
    if p.suffix.lower()!=".png" and report.get("kind")!="image":
        return []
    try:
        from PIL import Image
    except Exception:
        return []
    try:
        img=Image.open(p); img.load()
    except Exception:
        return []
    w,h=img.size
    if w*h>5_000_000:
        return []
    arts=[]
    try:
        rgba=img.convert("RGBA")
        pix=list(rgba.getdata())
        # Alpha exact bytes, alpha low bytes, sorted-by-hue RGB streams.
        streams={}
        streams["alpha_bytes"]=bytes(px[3] for px in pix[:1_000_000])
        streams["red_bytes"]=bytes(px[0] for px in pix[:1_000_000])
        streams["green_bytes"]=bytes(px[1] for px in pix[:1_000_000])
        streams["blue_bytes"]=bytes(px[2] for px in pix[:1_000_000])
        # Rainbow/hue clue: sort a bounded sample by HSV hue.
        import colorsys
        sample=pix[:min(len(pix),350000)]
        sorted_pix=sorted(sample,key=lambda px: colorsys.rgb_to_hsv(px[0]/255,px[1]/255,px[2]/255)[0])
        streams["hue_sorted_rgb"]=bytes([v for px in sorted_pix for v in px[:3]])[:800000]
        streams["hue_sorted_alpha"]=bytes(px[3] for px in sorted_pix)[:800000]
        useful=[]
        for name,bs in streams.items():
            txt=bs[:300000].decode("utf-8","ignore")
            printable="".join(chr(b) if 32<=b<127 or b in (9,10,13) else "." for b in bs[:200000])
            score=sl43_text_quality(printable)
            if score>70 or "ctf" in printable.lower() or "{" in printable:
                art=sl51_art(root,report,f"{name}.txt",printable[:300000],"sloper51_png_stream_text",260+min(score,200),f"PNG stream extraction: {name}")
                if art:
                    arts.append(art)
                    sl51_promote_text(report,printable,"SLOPER v51 PNG stream",art.get("path"),280)
                    useful.append({"stream":name,"score":score,"preview":printable[:2000]})
        # Generate manifest always for PNG stego review.
        manifest={"size":[w,h],"mode":img.mode,"streams_checked":list(streams.keys()),"useful":useful}
        art=sl51_art(root,report,"png_advanced_streams_manifest.json",json.dumps(manifest,indent=2,ensure_ascii=False),"sloper51_png_advanced_manifest",240,"PNG alpha/RGB/hue-sorted stream analysis.")
        if art: arts.append(art)
        if useful:
            report.setdefault("next_steps",[]).insert(0,{"priority":96,"step":"Review v51 PNG stream artifacts.","why":"Alpha/RGB/hue-sorted streams produced readable-looking text."})
    except Exception as e:
        sl51_trace(report,"PNGAdvanced failed",str(e),0)
    return arts
def sl51_run_agents(report, root, data):
    arts=[]
    try: arts += sl51_pyc_backdoor_agent(report,root,data)
    except Exception as e: sl51_trace(report,"PYC backdoor failed",str(e),0)
    try: arts += sl51_zip_path_agent(report,root,data)
    except Exception as e: sl51_trace(report,"ZIP path failed",str(e),0)
    try: arts += sl51_pcap_pure_agent(report,root,data)
    except Exception as e: sl51_trace(report,"Pure PCAP failed",str(e),0)
    try: arts += sl51_png_advanced_agent(report,root,data)
    except Exception as e: sl51_trace(report,"PNG advanced failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v51 = sl_run_agents
