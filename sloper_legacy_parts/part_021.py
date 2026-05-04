# Auto-split from sloper_legacy_monolith.py lines 18660-...
def sl56_run_agents(report, root, data):
    arts=[]
    for fn,name in [
        (sl56_repeating_xor_crib_agent,"crib xor"),
        (sl56_jwt_token_agent,"jwt token"),
        (sl56_image_bitplane_agent,"image bitplanes"),
    ]:
        try:
            arts += fn(report,root,data) or []
        except Exception as e:
            sl56_trace(report,name+" failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v56 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v56(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl56_trace(report,"previous agents failed",str(e),0)
    try:
        arts += sl56_run_agents(report,root,data) or []
    except Exception as e:
        sl56_trace(report,"v56 agents failed",str(e),0)
    return arts
def sl56_project_multifile_agent(pid):
    root=pdir(pid)
    meta=jread(meta_path(pid),{})
    files=[]
    for p in (root/"files").rglob("*"):
        if p.is_file() and not sl45_is_internal_generated_file(p,root):
            try:
                raw=p.read_bytes()
                if 1<=len(raw)<=2_000_000:
                    files.append({"path":p,"name":p.name,"data":raw})
            except Exception:
                pass
    if len(files)<2 or len(files)>24:
        return []
    outdir=root/"generated"/"sloper56_project"
    outdir.mkdir(parents=True,exist_ok=True)
    candidates=[]
    for i in range(len(files)):
        for j in range(i+1,len(files)):
            a=files[i]; b=files[j]
            n=min(len(a["data"]),len(b["data"]),500000)
            if n<4:
                continue
            ad=a["data"][:n]; bd=b["data"][:n]
            variants=[
                ("xor",bytes(ad[k]^bd[k] for k in range(n))),
                ("add",bytes((ad[k]+bd[k])&255 for k in range(n))),
                ("sub_a_b",bytes((ad[k]-bd[k])&255 for k in range(n))),
                ("sub_b_a",bytes((bd[k]-ad[k])&255 for k in range(n))),
            ]
            for method,raw in variants:
                txt=sl56_printable(raw[:200000])
                sc=sl56_score_text(txt)
                magic=[]
                try: magic=sl50_magic_kind(raw)
                except Exception: pass
                if sc>=130 or magic or "ctf_cs{" in txt.lower() or "flag{" in txt.lower():
                    fname=safe(f"{method}_{a['name']}_VS_{b['name']}.bin")[:160]
                    p=outdir/fname
                    p.write_bytes(raw)
                    candidates.append({"method":method,"file_a":a["name"],"file_b":b["name"],"size":n,"score":sc+(250 if magic else 0),"magic":magic,"preview":txt[:3000],"artifact":str(p)})
    if not candidates:
        return []
    candidates=sorted(candidates,key=lambda x:x["score"],reverse=True)[:80]
    manifest=outdir/"project_multifile_candidates.json"
    manifest.write_text(json.dumps(candidates,indent=2,ensure_ascii=False),encoding="utf-8")
    return [{"kind":"sloper56_project_multifile","name":manifest.name,"path":str(manifest),"url":"/api/raw?path="+str(manifest),"source":"CTF SLOPER v56","score":410,"note":"Project-level multi-file XOR/ADD/SUB candidates.","exists":True,"size":manifest.stat().st_size,"file":"project"}]
_prev_analyze_project_v56 = analyze_project
def analyze_project(pid):
    res=_prev_analyze_project_v56(pid)
    try:
        root=pdir(pid)
        rep=jread(report_path(pid),{})
        project_arts=sl56_project_multifile_agent(pid)
        if project_arts:
            rep.setdefault("summary",{}).setdefault("artifacts",[])
            rep["summary"]["artifacts"]=project_arts+rep["summary"].get("artifacts",[])
            rep["summary"].setdefault("sloper56_review_lanes",{})
            rep["summary"]["sloper56_review_lanes"]["v56_project_multifile"]=len(project_arts)
            rep["summary"].setdefault("sloper56_next_actions",[])
            rep["summary"]["sloper56_next_actions"].insert(0,{"priority":100,"step":"Open project_multifile_candidates.json.","why":"v56 combined project files with XOR/ADD/SUB; many CTFs hide data across two files."})
            # Promote flags from manifest previews
            txt=Path(project_arts[0]["path"]).read_text(encoding="utf-8",errors="ignore")
            for f in vf_primary_flags(txt,limit=12,scan_limit=500000):
                rep["summary"].setdefault("flags",[])
                rep["summary"]["flags"].insert(0,{"flag":f,"file":"project_multifile_candidates.json","score":620,"why":"v56 project-level multi-file operation produced flag-like text."})
            jwrite(report_path(pid),rep)
    except Exception:
        pass
    return res
_prev_project_summary_v56 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v56(reports, meta)
    artifacts=summary.get("artifacts",[]) or []
    lane=summary.get("sloper55_review_lanes",{}) or summary.get("sloper54_review_lanes",{}) or {}
    lane["v56_crib_xor"]=len([a for a in artifacts if "crib_xor" in a.get("name","")])
    lane["v56_jwt"]=len([a for a in artifacts if "jwt_token" in a.get("name","")])
    lane["v56_bitplanes"]=len([a for a in artifacts if "bitplane_contact_sheet" in a.get("name","")])
    lane["v56_project_multifile"]=lane.get("v56_project_multifile",0)
    summary["sloper56_review_lanes"]=lane
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper56" in txt or "v56" in txt: s+=12500
        if "project_multifile" in txt: s+=3000
        if "crib_xor" in txt: s+=2300
        if "bitplane" in txt: s+=1600
        if "jwt_token" in txt: s+=1200
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(artifacts,key=pri,reverse=True)[:7000]
    brief=summary.get("sloper55_project_brief",{}) or summary.get("sloper54_project_brief",{}) or {}
    brief["v56_multifile_pipeline"]="active"
    if lane.get("v56_project_multifile"): brief["inspect_first"]="project_multifile_candidates.json"
    elif lane.get("v56_crib_xor"): brief["inspect_first"]="crib_xor_candidates.json"
    elif lane.get("v56_bitplanes"): brief["inspect_first"]="bitplane_contact_sheet.png"
    elif lane.get("v56_jwt"): brief["inspect_first"]="jwt_token_decode.json"
    summary["sloper56_project_brief"]=brief
    matrix=summary.get("sloper55_coverage_matrix",{}) or summary.get("sloper54_coverage_matrix",{}) or {}
    matrix["project_multifile"]=lane.get("v56_project_multifile",0)
    matrix["crib_xor"]=lane.get("v56_crib_xor",0)
    matrix["jwt_tokens"]=lane.get("v56_jwt",0)
    matrix["bitplanes"]=lane.get("v56_bitplanes",0)
    summary["sloper56_coverage_matrix"]=matrix
    na=summary.get("sloper55_next_actions",[]) or summary.get("workflow_steps",[]) or []
    if lane.get("v56_project_multifile"):
        na.insert(0,{"priority":100,"step":"Open project_multifile_candidates.json.","why":"v56 combined project files with XOR/ADD/SUB."})
    if lane.get("v56_crib_xor"):
        na.insert(0,{"priority":99,"step":"Open crib_xor_candidates.json.","why":"v56 used flag-prefix known plaintext to recover possible XOR keys."})
    if lane.get("v56_bitplanes"):
        na.insert(0,{"priority":96,"step":"Open bitplane_contact_sheet.png.","why":"v56 generated visual bitplanes for image stego."})
    summary["sloper56_next_actions"]=na[:54]
    summary["workflow_steps"]=na[:54]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v56"
def sl57_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl56_trace(report, "v57:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v57:"+str(stage),
            "detail":str(detail)[:1800],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl57_art(root, report, name, content, kind="sloper57_artifact", score=260, note=""):
    outdir=root/"generated"/"sloper57"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v72","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl57_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl57_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl57_promote_text(report, text, source, artifact=None, score=310):
    try:
        sl45_promote_answer_markers(report,text,source,artifact,score)
    except Exception:
        pass
    try:
        for f in vf_primary_flags(str(text),limit=12,scan_limit=500000):
            if f not in report.setdefault("flags",[]):
                report["flags"].append(f)
                sl57_trace(report,"strict flag",f,score,artifact,f)
    except Exception:
        pass
def sl57_score_text(txt):
    txt=str(txt or "")
    try:
        score=sl43_text_quality(txt)
    except Exception:
        score=int(sum(1 for c in txt if 32<=ord(c)<127 or c in "\n\r\t")/max(1,len(txt))*100)
    low=txt.lower()
    for w in ["ctf_cs{","flag{","secret","password","token","cyber","sprint","raktas","slapta","admin","key"]:
        if w in low:
            score += 140
    if "{" in txt and "}" in txt:
        score += 80
    if re.search(r"[a-z0-9]{2,}_[a-z0-9_]{2,}",low):
        score += 70
    return score
def sl57_project_words_from_report(report):
    blob=""
    try:
        blob += ux_statement_text(report)+"\n"
    except Exception:
        pass
    try:
        blob += "\n".join(report.get("strings",[])[:300])+"\n"
    except Exception:
        pass
    blob += str(report.get("name",""))+"\n"+str(report.get("rel",""))+"\n"
    words=[]
    for tok in re.findall(r"[A-Za-z][A-Za-z0-9_]{2,31}",blob):
        clean=re.sub(r"[^A-Za-z]","",tok).lower()
        if 3<=len(clean)<=24 and clean not in words:
            words.append(clean)
    for w in ["ctf","cyber","sprint","secret","password","raktas","slapta","key","flag","admin","hidden"]:
        if w not in words:
            words.insert(0,w)
    return words[:120]
def sl57_caesar(s,shift):
    out=[]
    for ch in s:
        if "a"<=ch<="z":
            out.append(chr((ord(ch)-97+shift)%26+97))
        elif "A"<=ch<="Z":
            out.append(chr((ord(ch)-65+shift)%26+65))
        else:
            out.append(ch)
    return "".join(out)
def sl57_atbash(s):
    out=[]
    for ch in s:
        if "a"<=ch<="z":
            out.append(chr(122-(ord(ch)-97)))
        elif "A"<=ch<="Z":
            out.append(chr(90-(ord(ch)-65)))
        else:
            out.append(ch)
    return "".join(out)
def sl57_rot47(s):
    out=[]
    for ch in s:
        o=ord(ch)
        if 33<=o<=126:
            out.append(chr(33+((o-33+47)%94)))
        else:
            out.append(ch)
    return "".join(out)
_SL57_MORSE={
".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",
".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R",
"...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z",
"-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"
}
def sl57_morse_decode(s):
    s=str(s or "").strip()
    if not s or not re.fullmatch(r"[.\-/| _\n\r\t]+",s):
        return []
    variants=[]
    norm=s.replace("_","-").replace("|"," / ")
    # standard: spaces between letters, slash between words
    for sep in [" ","\n","\t"]:
        words=[]
        for word in re.split(r"\s*/\s*",norm):
            letters=[]
            for tok in [x for x in re.split(r"\s+",word.strip()) if x]:
                letters.append(_SL57_MORSE.get(tok,"?"))
            words.append("".join(letters))
        txt=" ".join(words)
        if txt and "?" not in txt:
            variants.append(txt)
        break
    # no spaces but slash groups, try split on slash only not safe; skip
    return list(dict.fromkeys(variants))
def sl57_bacon_decode(s):
    raw=re.sub(r"[^A-Za-z01]","",str(s or ""))
    if len(raw)<10:
        return []
    # accept A/B strings or 0/1 strings
    if re.fullmatch(r"[ABab]+",raw):
        bits="".join("0" if c.lower()=="a" else "1" for c in raw)
    elif re.fullmatch(r"[01]+",raw):
        bits=raw
    else:
        return []
    outs=[]
    alpha="ABCDEFGHIKLMNOPQRSTUWXYZ"  # classic 24-letter I/J, U/V style-ish
    alpha26="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for alph in [alpha26, alpha]:
        chars=[]
        for i in range(0,len(bits)-4,5):
            v=int(bits[i:i+5],2)
            if v < len(alph):
                chars.append(alph[v])
            else:
                chars.append("?")
        txt="".join(chars)
        if txt and txt.count("?")<max(1,len(txt)//8):
            outs.append(txt)
    return list(dict.fromkeys(outs))
def sl57_rail_fence_decrypt(cipher, rails):
    cipher=str(cipher)
    if rails<2 or len(cipher)<rails:
        return ""
    pattern=list(range(rails))+list(range(rails-2,0,-1))
    rail_idx=[pattern[i%len(pattern)] for i in range(len(cipher))]
    counts=[rail_idx.count(r) for r in range(rails)]
    rails_data=[]
    pos=0
    for c in counts:
        rails_data.append(list(cipher[pos:pos+c]))
        pos+=c
    out=[]
    ptr=[0]*rails
    for r in rail_idx:
        out.append(rails_data[r][ptr[r]])
        ptr[r]+=1
    return "".join(out)
def sl57_vigenere_decrypt(cipher, key):
    key=re.sub(r"[^A-Za-z]","",key).lower()
    if not key:
        return ""
    out=[]
    ki=0
    for ch in cipher:
        if ch.isalpha():
            base=65 if ch.isupper() else 97
            k=ord(key[ki%len(key)])-97
            out.append(chr((ord(ch)-base-k)%26+base))
            ki+=1
        else:
            out.append(ch)
    return "".join(out)
def sl57_classic_crypto_agent(report, root, data):
    data=bytes(data or b"")
    if not data or len(data)>2_000_000:
        return []
    p=Path(report.get("path",""))
    ext=p.suffix.lower()
    kind=report.get("kind","")
    allow=kind in ["text","generic","log","text_context","python_bytecode"] or ext in [".txt",".log",".md",".csv",".json",".dat",".enc",".cipher",".crypt",".py",".js",".php",""]
    if not allow and len(data)>400000:
        return []
    text=data[:500000].decode("utf-8","ignore")
    chunks=[]
    if text.strip():
        chunks.append(("full_text",text[:20000]))
    try:
        for line in text.splitlines()[:800]:
            line=line.strip()
            if 4<=len(line)<=5000:
                chunks.append(("line",line))
    except Exception:
        pass
    try:
        for s in report.get("strings",[])[:300]:
            if 4<=len(s)<=5000:
                chunks.append(("string",s))
    except Exception:
        pass
    keys=sl57_project_words_from_report(report)
    findings=[]
    seen=set()
    def add(method, source, output, meta=None):
        output=str(output or "")
        if not output:
            return
        score=sl57_score_text(output)
        if score<115 and "ctf" not in output.lower() and "{" not in output:
            return
        sig=(method,output[:120])
        if sig in seen:
            return
        seen.add(sig)
        item={"method":method,"source":source,"score":score,"output":output[:6000]}
        if meta:
            item.update(meta)
        findings.append(item)
        sl57_promote_text(report,output,"SLOPER v57 classic crypto",None,300+min(score,240))
    for source,chunk in chunks[:260]:
        # Caesar and ROT
        if re.search(r"[A-Za-z]",chunk):
            for sh in range(1,26):
                add(f"caesar_{sh}",source,sl57_caesar(chunk,sh),{"shift":sh})
            add("atbash",source,sl57_atbash(chunk))
            add("rot47",source,sl57_rot47(chunk))
            # Rail fence only for compact-ish alphabetic/symbol text, not huge paragraphs
            compact=re.sub(r"\s+","",chunk)
            if 8<=len(compact)<=800:
                for rails in range(2,9):
                    add(f"rail_fence_{rails}",source,sl57_rail_fence_decrypt(compact,rails),{"rails":rails})
            # Vigenere using clue words
            if 8<=len(chunk)<=3000:
                for key in keys[:80]:
                    if 3<=len(key)<=18:
                        add(f"vigenere_{key}",source,sl57_vigenere_decrypt(chunk,key),{"key":key})
        # Morse
        for out in sl57_morse_decode(chunk):
            add("morse",source,out)
        # Bacon
        for out in sl57_bacon_decode(chunk):
            add("bacon",source,out)
    if not findings:
        return []
    findings=sorted(findings,key=lambda x:x["score"],reverse=True)[:160]
    art=sl57_art(root,report,"classic_crypto_candidates.json",json.dumps(findings,indent=2,ensure_ascii=False),"sloper57_classic_crypto_candidates",390,"Classical crypto candidates: Caesar/Atbash/ROT47/Morse/Bacon/Rail fence/Vigenere.")
    if art:
        report.setdefault("next_steps",[]).insert(0,{"priority":98,"step":"Open classic_crypto_candidates.json.","why":"v57 tried classical CTF ciphers and clue-derived Vigenere keys."})
        return [art]
    return []
def sl57_solver_playbook_agent(report, root, data):
    p=Path(report.get("path",""))
    kind=report.get("kind","unknown")
    ext=p.suffix.lower() or "<none>"
    text=(ux_statement_text(report)+" "+report.get("name","")+" "+ext+" "+kind).lower()
    recommended=[]
    def rec(name,why):
        recommended.append({"workflow":name,"why":why})
    if any(k in text for k in ["xor","key","cipher","encrypt","užkodu","uzkodu","decode","crypto","morse","vigenere","caesar"]):
        rec("decode_graph / classic_crypto / crib_xor","Statement or filename suggests crypto/encoding.")
    if kind=="image" or ext in [".png",".jpg",".jpeg",".bmp",".gif",".webp"]:
        rec("visual_contact_sheet / bitplanes / lsb / palette / png streams","Image file detected.")
    if ext in [".pcap",".pcapng"]:
        rec("pcap field extraction / pure_pcap_covert_analysis","Network capture detected.")
    if ext in [".zip",".7z",".rar",".tar",".gz",".bz2",".xz"] or kind=="archive":
        rec("archive extraction / zip password wordlist / magic carving","Archive/compressed file detected.")
    if ext in [".elf",".exe",".so",".dll",".bin",""] or kind in ["binary","generic"]:
        rec("strings / constant arrays / transform_graph / magic_carve / entropy map","Binary or generic blob detected.")
    if ext in [".py",".js",".php",".java",".c",".cpp",".cs",".go",".rs"]:
        rec("source_deobf / constants / decode_graph","Source code file detected.")
    if not recommended:
        rec("strings / decode_graph / magic_carve / entropy map","Generic fallback workflows.")
    obj={
        "file":report.get("rel",report.get("name","")),
        "kind":kind,
        "extension":ext,
        "recommended_workflows":recommended,
        "strict_flags_seen":report.get("flags",[])[:10],
        "wrappers_seen":report.get("flag_wrapping_helpers",[])[:10],
        "note":"This is a playbook, not a final answer. Use it to decide the next artifact to inspect."
    }
    art=sl57_art(root,report,"solver_playbook.json",json.dumps(obj,indent=2,ensure_ascii=False),"sloper57_solver_playbook",300,"Per-file workflow playbook and next-step reasoning.")
    return [art] if art else []
def sl57_run_agents(report, root, data):
    arts=[]
    for fn,name in [
        (sl57_classic_crypto_agent,"classic crypto"),
        (sl57_solver_playbook_agent,"solver playbook"),
    ]:
        try:
            arts += fn(report,root,data) or []
        except Exception as e:
            sl57_trace(report,name+" failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v57 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v57(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl57_trace(report,"previous agents failed",str(e),0)
    try:
        arts += sl57_run_agents(report,root,data) or []
    except Exception as e:
        sl57_trace(report,"v57 agents failed",str(e),0)
    return arts
_prev_project_summary_v57 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v57(reports, meta)
    artifacts=summary.get("artifacts",[]) or []
    lane=summary.get("sloper56_review_lanes",{}) or summary.get("sloper55_review_lanes",{}) or {}
    lane["v57_classic_crypto"]=len([a for a in artifacts if "classic_crypto" in a.get("name","") or "sloper57_classic" in a.get("kind","")])
    lane["v57_playbooks"]=len([a for a in artifacts if "solver_playbook" in a.get("name","")])
    summary["sloper57_review_lanes"]=lane
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper57" in txt or "v57" in txt: s+=13500
        if "classic_crypto" in txt: s+=2600
        if "solver_playbook" in txt: s+=700
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(artifacts,key=pri,reverse=True)[:7500]
    brief=summary.get("sloper56_project_brief",{}) or summary.get("sloper55_project_brief",{}) or {}
    brief["v57_reasoning_pipeline"]="active"
    if lane.get("v57_classic_crypto"): brief["inspect_first"]="classic_crypto_candidates.json"
    summary["sloper57_project_brief"]=brief
    matrix=summary.get("sloper56_coverage_matrix",{}) or summary.get("sloper55_coverage_matrix",{}) or {}
    matrix["classic_crypto"]=lane.get("v57_classic_crypto",0)
    matrix["solver_playbooks"]=lane.get("v57_playbooks",0)
    summary["sloper57_coverage_matrix"]=matrix
    na=summary.get("sloper56_next_actions",[]) or summary.get("workflow_steps",[]) or []
    if lane.get("v57_classic_crypto"):
        na.insert(0,{"priority":99,"step":"Open classic_crypto_candidates.json.","why":"v57 tried Caesar/Atbash/ROT47/Morse/Bacon/Rail fence/Vigenere using clue keys."})
    if lane.get("v57_playbooks"):
        na.append({"priority":60,"step":"Open solver_playbook.json if stuck.","why":"v57 generated per-file workflow recommendations."})
    summary["sloper57_next_actions"]=na[:58]
    summary["workflow_steps"]=na[:58]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v72"
def index(): return (BASE/"static/index.html").read_text(encoding="utf-8")
def raw(path:str):
    p=Path(path).resolve()
    if not str(p).startswith(str(BASE)): return JSONResponse({"error":"blocked"},status_code=403)
    if not p.exists(): return JSONResponse({"error":"not found"},status_code=404)
    return FileResponse(str(p))
async def create_project(background_tasks:BackgroundTasks,title:str=Form(...),statement:str=Form(""),category:str=Form("auto"),auto_start:str=Form("true"),files:List[UploadFile]=File(...)):
    pid=uuid.uuid4().hex[:12]; root=pdir(pid); fdir=root/"files"; fdir.mkdir(parents=True)
    meta={"id":pid,"title":title,"statement":statement,"category":category,"created":now(),"file_count":len(files)}
    jwrite(meta_path(pid),meta)
    for f in files: (fdir/safe(f.filename)).write_bytes(await f.read())
    with LOCK: JOBS[pid]={"status":"created","progress":0,"stage":"Created","updated":time.time()}
    log(pid,f"Project created: {title}")
    if auto_start.lower()=="true":
        with LOCK: JOBS[pid]["status"]="running"
        background_tasks.add_task(analyze_project,pid)
    return {"id":pid,"project":meta}
def list_projects():
    arr=[]
    for d in sorted([x for x in PROJECTS.iterdir() if x.is_dir()],reverse=True):
        meta=jread(d/"project.json",{}); rep=jread(d/"report.json",{}); job=JOBS.get(meta.get("id"),{})
        meta.update({"progress":job.get("progress",100 if rep else 0),"stage":job.get("stage","Done" if rep else "idle"),"runtime_status":job.get("status","done" if rep else "idle"),"summary":rep.get("summary",{})})
        arr.append(meta)
    return {"projects":arr}
def start_project(pid:str,background_tasks:BackgroundTasks):
    if not meta_path(pid).exists(): return JSONResponse({"error":"not found"},status_code=404)
    with LOCK: JOBS[pid]={"status":"running","progress":0,"stage":"Queued","updated":time.time()}
    background_tasks.add_task(analyze_project,pid); return {"ok":True}
def get_project(pid:str):
    return {"project":jread(meta_path(pid),{}),"report":jread(report_path(pid),{}),"job":JOBS.get(pid,{}),"log":(pdir(pid)/"events.log").read_text(encoding="utf-8") if (pdir(pid)/"events.log").exists() else ""}
async def ask_project(pid:str,question:str=Form(...),model:str=Form("deepseek-r1:14b")):
    rep=jread(report_path(pid),{}); meta=jread(meta_path(pid),{}); context=rep.get("ai_prompt") or ai_prompt(meta,rep.get("files",[]))
    prompt="You are the AI operator inside a local CTF project. Target ctf_cs{...}. Use Evidence Board, Chain Results, intermediate files, and workflow steps. Give exact UI/tool actions and proof.\\n\\nCONTEXT:\\n"+context+"\\n\\nQUESTION:\\n"+question
    try:
        r=requests.post("http://127.0.0.1:11434/api/generate",json={"model":model,"prompt":prompt,"stream":False},timeout=300)
        out=r.json().get("response","")
    except Exception as e: out="Ollama unavailable: "+str(e)
    return {"ok":True,"out":out}
def tool_status():
    items=[]
    for name in sorted(TOOL_COMMANDS.keys()):
        deps=TOOL_DEPS.get(name,[])
        miss=[d for d in deps if not exists(d)]
        items.append({"name":name,"deps":deps,"installed":not miss,"missing":miss})
    return {"tools":items,"virtual_profiles":jread(BASE/"data/tool_catalog_v20.json",{}).get("virtual_profiles",[])[:1000]}
async def run_tool_endpoint(path:str=Form(...),toolname:str=Form(...)):
    return run_tool_local(path,toolname,180)
async def run_tool_suite(path:str=Form(...),suite:str=Form("quick")):
    p=Path(path)
    if not p.exists(): return {"ok":False,"error":"file not found","results":[]}
    k,tools=suite_for_path(p,suite)
    results=[run_tool_local(p,t,180) for t in tools[:50]]
    return {"ok":True,"kind":k,"suite":suite,"tools":tools,"results":results,"derived":summarize_suite(results)}
async def run_verifyloop_endpoint(path:str=Form(...)):
    p=Path(path)
    if not p.exists():
        return {"ok":False,"error":"file not found"}
    try:
        data=readbytes(p)
        fileout=run(["file",str(p)],20).get("out","") if exists("file") else ""
        kind=detect_kind(p,fileout)
        ss=py_strings(data)
        temp={"name":p.name,"path":str(p),"rel":p.name,"kind":kind,"file":fileout,"strings":ss[:1400],"outputs":[],"previews":[],"flags":list(dict.fromkeys(x.decode("utf-8","replace") for x in FLAG_BYTES_RE.findall(data))),"decoders":[],"chain_results":[],"expert_contexts":[],"transformations":[],"intermediate_files":[],"agent_files":[]}
        # For image, also run image lab immediately.
        root = p.parent if p.parent.exists() else BASE
        if kind=="image":
            pv, outs = image_lab(p, root)
            temp["previews"] += pv
            temp["outputs"] += outs
        temp["verifyloop"] = verifyloop_run_tools("manual", p, temp, root)
        verifyloop_refresh_analysis(temp, data)
        temp["transformations"] = execute_transform_agents(temp, root, data)
        temp["intermediate_files"] = temp.get("transformations", [])[:320]
        temp["agent_runs"], temp["agent_files"] = run_agent_forge(temp, root)
        verifyloop_scan_transform_files(temp)
        verifyloop_refresh_analysis(temp, data)
        apply_verified_flags(temp)
        temp["findings"] = rank_findings(temp)
        temp["next_steps"] = next_steps(temp)
        return {"ok":True,"kind":kind,"verifyloop":temp.get("verifyloop",{}),"findings":temp.get("findings",[])[:100],"flags":temp.get("flags",[]),"chain_results":temp.get("chain_results",[])[:120],"transformations":temp.get("transformations",[])[:160],"agents":temp.get("agent_runs",[])[:80],"previews":temp.get("previews",[])[:40]}
    except Exception as e:
        return {"ok":False,"error":str(e)}
async def run_transforms_endpoint(path:str=Form(...)):
    p=Path(path)
    if not p.exists():
        return {"ok":False,"error":"file not found"}
    try:
        data=readbytes(p)
        fileout=run(["file",str(p)],20).get("out","") if exists("file") else ""
        kind=detect_kind(p,fileout)
        ss=py_strings(data)
        temp={"name":p.name,"path":str(p),"rel":p.name,"kind":kind,"file":fileout,"strings":ss[:1200],"outputs":[],"previews":[],"flags":list(dict.fromkeys(x.decode("utf-8","replace") for x in FLAG_BYTES_RE.findall(data))),"decoders":decode_candidates("\n".join(ss[:1800]),data)[:120],"chain_results":[],"expert_contexts":[]}
        temp["chain_results"]=chain_decode_report(temp,data) if "chain_decode_report" in globals() else temp["decoders"]
        transforms=execute_transform_agents(temp, p.parent if p.parent.exists() else BASE, data)
        derived_text="\n".join(Path(t["path"]).read_text(encoding="utf-8",errors="ignore")[:5000] for t in transforms if Path(t.get("path","")).exists() and Path(t.get("path","")).suffix.lower() in [".txt",".json",".log",".agent.txt"])
        return {"ok":True,"kind":kind,"transformations":transforms,"evidence":extract_flagish_text(derived_text)[:80],"decoders":decode_candidates(derived_text,b"")[:80]}
    except Exception as e:
        return {"ok":False,"error":str(e)}
async def run_agents_endpoint(path:str=Form(...)):
    p=Path(path)
    if not p.exists():
        return {"ok":False,"error":"file not found"}
    try:
        data=readbytes(p)
        fileout=run(["file",str(p)],20).get("out","") if exists("file") else ""
        kind=detect_kind(p,fileout)
        ss=py_strings(data)
        temp={"name":p.name,"path":str(p),"rel":p.name,"kind":kind,"file":fileout,"strings":ss[:900],"outputs":[],"previews":[],"flags":list(dict.fromkeys(x.decode("utf-8","replace") for x in FLAG_BYTES_RE.findall(data))),"chain_results":decode_candidates("\n".join(ss[:1800]),data)[:100],"hypotheses":[],"structured_clues":[]}
        temp["structured_clues"]=detect_structured_clues("\n".join(ss[:1800]))
        temp["hypotheses"]=classify_workflow_hypotheses(temp)
        agents, files = run_agent_forge(temp, p.parent if p.parent.exists() else BASE)
        return {"ok":True,"kind":kind,"agents":agents,"agent_files":files,"hypotheses":temp["hypotheses"],"structured_clues":temp["structured_clues"]}
    except Exception as e:
        return {"ok":False,"error":str(e)}
async def image_transform(path:str=Form(...),op:str=Form(...),value:str=Form("1")):
    p=Path(path)
    if not p.exists(): return {"ok":False,"out":"file not found"}
    im=Image.open(p).convert("RGB"); outdir=p.parent/"manual_image_ops"/p.stem; outdir.mkdir(parents=True,exist_ok=True)
    if op=="grayscale": out=ImageOps.grayscale(im)
    elif op=="invert": out=ImageOps.invert(im)
    elif op=="autocontrast": out=ImageOps.autocontrast(im)
    elif op=="edges": out=im.filter(ImageFilter.FIND_EDGES)
    elif op=="sharpen": out=im.filter(ImageFilter.SHARPEN)
    elif op=="emboss": out=im.filter(ImageFilter.EMBOSS)
    elif op=="contrast": out=ImageEnhance.Contrast(im).enhance(float(value))
    elif op=="brightness": out=ImageEnhance.Brightness(im).enhance(float(value))
    elif op.startswith("bitplane_"):
        _,ch,b=op.split("_"); arr=np.array(im)[:,:,"RGB".index(ch)]; out=Image.fromarray(((arr>>int(b))&1).astype(np.uint8)*255)
    else: return {"ok":False,"out":"unknown op"}
    outpath=outdir/(op+"_"+str(value).replace(".","_")+".png"); out.save(outpath)
    ocr=ocr_path(outpath); qr=qr_path(outpath); sc,flags=score_visual(op,ocr,qr)
    return {"ok":True,"url":"/api/raw?path="+str(outpath),"score":sc,"ocr":ocr,"qr":qr,"flags":flags}
async def decode_endpoint(text:str=Form(...)):
    return {"items":decode_candidates(text,text.encode(errors="ignore"))}
def tools():
    return jread(BASE/"data/tool_catalog_v20.json",{})
async def setup(action:str=Form(...)):
    if action=="python": return run(["python3","-m","pip","install","--user","-r",str(BASE/"requirements.txt")],180)
    if action=="check": return {"ok":True,"out":json.dumps(tool_status(),indent=2)}
    return {"ok":True,"out":"Full setup:\\ncd "+str(BASE)+"\\nbash FULL_INSTALL.sh\\nbash START_HERE.sh"}
async def ask(prompt:str=Form(...),model:str=Form("deepseek-r1:14b")):
    try:
        r=requests.post("http://127.0.0.1:11434/api/generate",json={"model":model,"prompt":prompt,"stream":False},timeout=300)
        return {"ok":True,"out":r.json().get("response","")}
    except Exception as e: return {"ok":False,"out":"Ollama unavailable: "+str(e)}
BRACE_PREFIX_RE_V91 = re.compile(r"(?:ctf_cs|ctf|flag|cyber|sprint|tsg|cs|nksc|ctf_cm)?\{[^}\r\n]{1,260}\}", re.I)
COMMON_CONFIG_KEYS_V91 = {"version","name","description","author","license","type","main","scripts","dependencies","data","items","meta","id","url","href","class","style","width","height","title"}
def sl91_inner(flag):
    m=re.search(r"\{([^}\r\n]{1,260})\}", str(flag or "")); return m.group(1) if m else ""
def sl91_body_quality(inner, context=""):
    inner=str(inner or "").strip(); low=inner.lower(); ctx=str(context or "").lower(); score=0
    if not (3 <= len(inner) <= 160): return -999
    if low in COMMON_CONFIG_KEYS_V91: return -200
    if re.fullmatch(r"[A-Za-z0-9_!@#$%^&*+\-=:;,.?/|~]+", inner): score+=18
    if "_" in inner: score+=14
    if re.search(r"[A-Za-z]", inner) and re.search(r"\d", inner): score+=10
    if re.search(r"[{}\[\]\n\r<>]", inner): score-=80
    if any(w in low for w in FALSE_FLAG_WORDS): score-=160
    if re.fullmatch(r"[0-9,.:\- ]+", inner): score-=80
    if len(set(inner)) <= 2 and len(inner)>8: score-=60
    if any(k in ctx for k in ["flag","answer","submit","decoded","decrypted","hidden","secret","raktas","slapta","veliava","final"]): score+=22
    if any(k in low for k in ["flag","ctf","secret","hidden","slapta","raktas","key"]): score+=16
    return score
def fast_flag_matches(text, limit=40, scan_limit=20000):
    text=str(text or "")[:scan_limit]
    if "{" not in text or "}" not in text: return []
    hits=[]; seen=set()
    for m in BRACE_PREFIX_RE_V91.finditer(text):
        cand=m.group(0)
        if len(cand)>280 or "\n" in cand or "\r" in cand: continue
        inner=sl91_inner(cand); ctx=text[max(0,m.start()-180):min(len(text),m.end()+180)]
        pref=bool(re.match(r"(?i)^(ctf_cs|ctf|flag|cyber|sprint|tsg|cs|nksc|ctf_cm)\{", cand))
        q=sl91_body_quality(inner,ctx)
        if cand.startswith("{") and not pref:
            if q < 18: continue
            if re.search(r"[:=]\s*"+re.escape(cand), ctx) and "flag" not in ctx.lower(): continue
        if cand.lower() not in seen:
            seen.add(cand.lower()); hits.append(cand)
        if len(hits)>=limit: break
    return hits[:limit]
def sl91_try_decimal_offsets(s):
    outs=[]
    try:
        nums=[int(x) for x in re.findall(r"-?\d+", str(s or ""))]
        if 4 <= len(nums) <= 500:
            for off in [0,1,7,10,32,64,100,1000,-1,-7,-10,-32,-64,-100,-1000]:
                vals=[n-off for n in nums]
                if all(0 <= v <= 255 for v in vals):
                    txt=bytes(vals).decode("utf-8","replace")
                    if score_text(txt)>18 or fast_flag_matches(txt,1): outs.append((f"decimal_offset_minus_{off}",txt))
            for x in [1,7,13,23,42,85,127,255]:
                vals=[n^x for n in nums]
                if all(0 <= v <= 255 for v in vals):
                    txt=bytes(vals).decode("utf-8","replace")
                    if score_text(txt)>30 or fast_flag_matches(txt,1): outs.append((f"decimal_xor_{x}",txt))
    except Exception: pass
    return outs[:20]
def sl91_rail_fence_decode(s, rails):
    s=str(s or "")
    if rails < 2 or len(s)<8: return ""
    try:
        pattern=list(range(rails))+list(range(rails-2,0,-1)); ids=[pattern[i%len(pattern)] for i in range(len(s))]
        counts=[ids.count(r) for r in range(rails)]; rails_text=[]; idx=0
        for c in counts: rails_text.append(list(s[idx:idx+c])); idx+=c
        pos=[0]*rails; out=[]
        for r in ids: out.append(rails_text[r][pos[r]]); pos[r]+=1
        return ''.join(out)
    except Exception: return ""
def decode_candidates(text, data=b""):
    outs=[]; seen=set(); text=str(text or "")[:30000]
    def add(t,i,o,base=0):
        if not o: return
        o=str(o)[:12000]; key=(t,o[:300])
        if key in seen: return
        seen.add(key); flags=fast_flag_matches(o, limit=10, scan_limit=12000)
        sc=int(base)+score_text(o)+(130 if flags else 0)
        if sc>=18 or flags or re.search(r"[A-Za-z0-9+/=_-]{16,}|[0-9a-fA-F]{16,}", o):
            outs.append({"type":t,"input":str(i)[:320],"output":o,"flags":flags,"score":sc})
    chunks=re.findall(r"[A-Za-z0-9+/=_-]{8,}|[A-Z2-7=]{8,}|[!-u]{10,}|[0-9a-fA-F]{8,}|(?:[01]{8}\s*){2,}|(?:[0-7]{2,3}\s+){2,}[0-7]{2,3}|(?:-?\d{1,5}[,;:\s]+){3,}-?\d{1,5}|(?:[.\-]{1,6}\s+){3,}[.\-]{1,6}",text)[:600]
    for raw in chunks:
        s=raw.strip().strip('"\'`')
        if not s or len(s)>2500: continue
        try:
            if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}",s):
                padded=s+"="*((4-len(s)%4)%4); rawb=base64.b64decode(padded,validate=False)
                add("base64",s,rawb.decode("utf-8","replace"),10); add("base64_urlsafe",s,base64.urlsafe_b64decode(padded).decode("utf-8","replace"),12)
                if rawb.startswith(b"\xff\xfe") or rawb[1:2]==b"\x00": add("base64_utf16le",s,rawb.decode("utf-16le","replace"),20)
        except Exception: pass
        try:
            if re.fullmatch(r"[A-Z2-7=]{8,}",s): add("base32",s,base64.b32decode(s+"="*((8-len(s)%8)%8)).decode("utf-8","replace"),8)
        except Exception: pass
        try:
            b58=try_base58(s)
            if b58 and (score_text(b58)>18 or fast_flag_matches(b58,1)): add("base58",s,b58,12)
        except Exception: pass
        try:
            a85=try_ascii85(s)
            if a85 and (score_text(a85)>18 or fast_flag_matches(a85,1)): add("base85_ascii85",s,a85,12)
        except Exception: pass
        try:
            h=re.sub(r"\s+","",s)
            if len(h)%2==0 and re.fullmatch(r"[0-9a-fA-F]{8,}",h): add("hex",s,bytes.fromhex(h).decode("utf-8","replace"),10)
        except Exception: pass
        try:
            bits=re.sub(r"\s+","",s)
            if len(bits)%8==0 and re.fullmatch(r"[01]{16,}",bits): add("binary",s,bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8)).decode("utf-8","replace"),10)
        except Exception: pass
        try:
            parts=s.split()
            if len(parts)>2 and all(re.fullmatch(r"[0-7]{2,3}",x) for x in parts):
                vals=[int(x,8) for x in parts]
                if all(0 <= v <= 255 for v in vals):
                    add("octal",s,bytes(vals).decode("utf-8","replace"),10)
        except Exception: pass
        try:
            ac=try_ascii_codes(s)
            if ac and (score_text(ac)>18 or fast_flag_matches(ac,1)): add("ascii_codes",s,ac,14)
        except Exception: pass
        for nm,out in sl91_try_decimal_offsets(s): add(nm,s,out,16)
        try:
            md=morse_decode(s)
            if md and "?" not in md[:20]: add("morse",s,md,10)
        except Exception: pass
    visible=text[:12000]
    try:
        if "\\x" in visible or "\\u" in visible or "\\n" in visible: add("python_escape","visible",bytes(visible,"utf-8").decode("unicode_escape"),12)
    except Exception: pass
    try: add("quoted_printable","visible",__import__('quopri').decodestring(visible).decode("utf-8","replace"),10)
    except Exception: pass
    add("url_decode","visible",urllib.parse.unquote(visible),8); add("html_unescape","visible",html.unescape(visible),8)
    if len(visible)<=7000:
        add("atbash","visible",atbash(visible),8); add("reverse_text","visible",visible[::-1],8)
        compact=re.sub(r"\s+","",visible)
        for r in range(2,7):
            rf=sl91_rail_fence_decode(compact,r)
            if rf and (score_text(rf)>30 or fast_flag_matches(rf,1)): add(f"rail_fence_{r}","visible",rf,12)
    bacon=try_bacon(visible)
    if bacon and (score_text(bacon)>18 or fast_flag_matches(bacon,1)): add("bacon_ab","visible",bacon,15)
    if len(visible)<=3500:
        a="abcdefghijklmnopqrstuvwxyz"; A=a.upper()
        for r in range(1,26): add(f"rot{r}","visible",visible.translate(str.maketrans(a+A,a[r:]+a[:r]+A[r:]+A[:r])),6)
    for hit in extract_flagish_text(visible): add(hit["type"],"flag/brace hunter",hit["value"],hit["score"])
    for ctx in expert_context_lines(visible)[:60]: add("context_near_flag_or_brace","context hunter",ctx,18)
    if data: outs += xor_single(data)[:20] + repeating_xor_guesses(data)[:14] + try_decompress_bytes(data)[:12] + xor_crib_ctf_cs(data)[:10]
    return sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:360]
def recursive_decode_seed(text,max_rounds=4):
    text=str(text or "")[:14000]; results=[]; seen=set(); frontier=[("input",text)]
    for depth in range(max_rounds):
        new=[]
        for label,val in frontier[:18]:
            key=(label,val[:260])
            if key in seen: continue
            seen.add(key)
            for item in decode_candidates(val,b"")[:28]:
                out=(item.get("output","") or "")[:12000]; item=dict(item); item["output"]=out; item["type"]=f"{label}->{item['type']}"; item["score"]=item.get("score",0)+depth*10
                results.append(item)
                encodedish=bool(re.search(r"[A-Za-z0-9+/=_-]{16,}|[0-9a-fA-F]{16,}|(?:[01]{8}\s*){3,}|(?:\d{2,5}[,;:\s]+){4,}", out))
                if out and len(new)<14 and (score_text(out)>22 or encodedish or fast_flag_matches(out,1)): new.append((item["type"],out))
        frontier=new[:14]
        if not frontier: break
    return sorted(results,key=lambda x:x.get("score",0),reverse=True)[:140]
def add_flag_source(bucket,flag,source,context="",base=0):
    flag=normalize_flag_candidate(flag)
    if not flag or "{" not in flag or "}" not in flag: return
    inner=flag_inner(flag); q=sl91_body_quality(inner, context)
    if q < -100: return
    key=flag.lower(); item=bucket.setdefault(key,{"flag":flag,"sources":[],"contexts":[],"score":0,"reasons":[],"negative_reasons":[]})
    item["sources"].append(str(source)[:240])
    if context: item["contexts"].append(str(context)[:900])
    item["score"] += source_weight(source)+int(base)+q
    low=flag.lower()
    if low.startswith("ctf_cs{"): item["score"]+=80; item["reasons"].append("matches target ctf_cs{...} format")
    elif re.match(r"(?i)^(flag|ctf|tsg|cyber|sprint|ctf_cm|nksc)\{", flag): item["score"]+=45; item["reasons"].append("known alternate CTF wrapper")
    else: item["score"]+=28; item["reasons"].append("bare {...} flag candidate")
    if 5<=len(inner)<=96: item["score"]+=18; item["reasons"].append("reasonable flag body length")
    if any(w in (context or "").lower() for w in ["decoded","decrypted","success","found","output","hidden","secret","raktas","slapta","answer","submit","final"]): item["score"]+=28; item["reasons"].append("supportive solve-context words nearby")
    neg=is_flag_placeholder(flag,context,source)
    if neg: item["negative_reasons"].extend(neg); item["score"]-=120+35*len(neg)
def apply_verified_flags(report):
    verified=collect_verified_flags(report); report["verified_flags"]=verified
    report["flags"]=[v["flag"] for v in verified if v.get("status") in ["confirmed","likely"] and not v.get("negative_reasons")]
    return report
_prev_v91_decode_candidates = decode_candidates
def decode_candidates(text, data=b""):
    outs = list(_prev_v91_decode_candidates(text, data))
    seen={(x.get('type'), (x.get('output','') or '')[:300]) for x in outs}
    def add(t,o,base=0):
        if not o: return
        o=str(o)[:12000]; key=(t,o[:300])
        if key in seen: return
        seen.add(key); flags=fast_flag_matches(o, limit=10, scan_limit=12000)
        sc=int(base)+score_text(o)+(140 if flags else 0)
        if flags or sc>=35:
            outs.append({"type":t,"input":"v91b split/join","output":o,"flags":flags,"score":sc})
    visible=str(text or "")[:12000]
    # Common CTF trick: flag characters split by commas, spaces, newlines, pipes, or CSV cells.
    compact=re.sub(r"(?<=[A-Za-z0-9_{}!@#$%^&*+\-=:;,.?/|~])[,;|\s]+(?=[A-Za-z0-9_{}!@#$%^&*+\-=:;,.?/|~])", "", visible)
    if compact != visible and ("{" in compact and "}" in compact): add("separator_join_compact", compact, 35)
    # Also try joining quoted CSV-ish cells: "c","t","f","{",...
    cells=re.findall(r"['\"]([^'\"]{1,8})['\"]", visible)
    if 4 <= len(cells) <= 500:
        joined=''.join(cells)
        if "{" in joined and "}" in joined: add("quoted_cell_join", joined, 40)
    return sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:380]
SL92_VISUAL_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tif", ".tiff"}
try:
    import importlib as _sl92_importlib
except Exception:
    _sl92_importlib = None
def sl92_url(path):
    return "/api/raw?path=" + str(path)
