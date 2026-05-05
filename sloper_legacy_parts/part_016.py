# Auto-split from sloper_legacy_monolith.py lines 14148-...
def sl45_project_has_fast_archive(root):
    try:
        files_dir=Path(root)/"files"
        return any(p.is_file() and sl45_is_fast_archive_path(p) for p in files_dir.rglob("*") if "_sloper" not in str(p))
    except Exception:
        return False
def sl45_fast_archive_project(pid):
    root=pdir(pid); meta=jread(meta_path(pid),{})
    reports=[]
    files_dir=root/"files"
    files=[p for p in files_dir.rglob("*") if p.is_file() and "_sloper" not in str(p)]
    # Fast archives first, other files only if no flag found.
    files=sorted(files,key=lambda p:(0 if sl45_is_fast_archive_path(p) else 1, str(p)))
    total=max(1,len(files))
    progress(pid,2,"v45 fast archive project mode")
    for i,p in enumerate(files,1):
        try:
            if sl45_is_fast_archive_path(p):
                progress(pid,min(90,5+i*10),f"v45 fast archive {p.name}")
                rep=sl45_fast_archive_analyze_file(pid,p,root,i,total)
                reports.append(rep)
                # If archive chain solves, stop before legacy heavy analysis.
                if rep.get("flags"):
                    break
            else:
                # Only analyze non-archive files if no flag yet, and keep it bounded.
                if any(r.get("flags") for r in reports):
                    break
                progress(pid,min(80,5+i*10),f"analyze {p.name}")
                reports.append(_prev_analyze_file_v45_fast_archive(pid,p,root,i,total))
        except Exception as e:
            reports.append({"id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":str(p.relative_to(root)),"kind":"error","error":str(e),"flags":[],"strings":[],"outputs":[],"previews":[],"commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"findings":[{"score":20,"type":"v45_fast_project_error","value":str(e),"why":"Fast archive project path failed."}],"next_steps":[{"priority":20,"step":"Inspect manually; v45 fast project path failed.","why":str(e)}]})
        jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    progress(pid,100,"Done")
    jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    with LOCK: JOBS.setdefault(pid,{})["status"]="done"
_prev_analyze_project_v45_fast_archive = analyze_project
def analyze_project(pid):
    try:
        root=pdir(pid)
        if sl45_project_has_fast_archive(root):
            return sl45_fast_archive_project(pid)
    except Exception:
        pass
    return _prev_analyze_project_v45_fast_archive(pid)
def sl45_is_internal_generated_file(p, root=None):
    try:
        p=Path(p)
        parts=set(p.parts)
        # Only skip generated/autopass internal folders, not the whole ctf_sloper project name.
        if "generated" in parts or "batches" in parts or "__pycache__" in parts:
            return True
        if any(part.startswith("_sloper") for part in p.parts):
            return True
        return False
    except Exception:
        return False
def sl45_project_has_fast_archive(root):
    try:
        files_dir=Path(root)/"files"
        for p in files_dir.rglob("*"):
            if p.is_file() and not sl45_is_internal_generated_file(p,root) and sl45_is_fast_archive_path(p):
                return True
        return False
    except Exception:
        return False
def sl45_fast_archive_project(pid):
    root=pdir(pid); meta=jread(meta_path(pid),{})
    reports=[]
    files_dir=root/"files"
    files=[p for p in files_dir.rglob("*") if p.is_file() and not sl45_is_internal_generated_file(p,root)]
    files=sorted(files,key=lambda p:(0 if sl45_is_fast_archive_path(p) else 1, str(p)))
    total=max(1,len(files))
    progress(pid,2,"v45 fast archive project mode")
    for i,p in enumerate(files,1):
        try:
            if sl45_is_fast_archive_path(p):
                progress(pid,min(90,5+i*10),f"v45 fast archive {p.name}")
                rep=sl45_fast_archive_analyze_file(pid,p,root,i,total)
                reports.append(rep)
                if rep.get("flags"):
                    break
            else:
                if any(r.get("flags") for r in reports):
                    break
                progress(pid,min(80,5+i*10),f"bounded analyze {p.name}")
                reports.append(_prev_analyze_file_v45_fast_archive(pid,p,root,i,total))
        except Exception as e:
            reports.append({"id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":str(p.relative_to(root)),"kind":"error","error":str(e),"flags":[],"strings":[],"outputs":[],"previews":[],"commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"findings":[{"score":20,"type":"v45_fast_project_error","value":str(e),"why":"Fast archive project path failed."}],"next_steps":[{"priority":20,"step":"Inspect manually; v45 fast project path failed.","why":str(e)}]})
        jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    progress(pid,100,"Done")
    jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    with LOCK: JOBS.setdefault(pid,{})["status"]="done"
def sl46_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl45_trace(report, "v46:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v46:"+str(stage),
            "detail":str(detail)[:1300],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl46_art(root, report, name, content, kind="sloper46_artifact", score=170, note=""):
    outdir=root/"generated"/"sloper46"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v46","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl46_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl46_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl46_statement_wants_sha256(report_or_meta):
    txt=""
    if isinstance(report_or_meta,dict):
        txt=(report_or_meta.get("statement","") or "")+" "+(report_or_meta.get("title","") or "")+" "+ux_statement_text(report_or_meta)
    else:
        txt=str(report_or_meta or "")
    return "sha256" in txt.lower() or "sha-256" in txt.lower()
def sl46_promote_sha256_answer(report, text, source, artifact=None, score=330):
    text=str(text or "").strip()
    if not text:
        return 0
    # Hash the full candidate and selected normalized variants.
    variants=[]
    variants.append(text)
    if "\n" in text:
        lines=[x.strip() for x in text.splitlines() if x.strip()]
        variants += lines[:40]
    # Strip decorative/label wrappers.
    variants += [re.sub(r"(?i)^(decoded|message|pranešimas|pranesimas|answer|flag)\s*[:=]\s*","",v).strip() for v in variants]
    out=[]; seen=set()
    for v in variants:
        v=v.strip()
        if not v or len(v)>10000: continue
        for vv in [v, v+"\n"]:
            h=hashlib.sha256(vv.encode()).hexdigest()
            if h not in seen:
                seen.add(h); out.append({"input":v,"input_len":len(v),"sha256":h})
                cand=f"ctf_cs{{{h}}}"
                if cand not in report.setdefault("flags",[]):
                    report["flags"].append(cand)
                report.setdefault("answer_candidates",[]).append({"value":h,"source":source,"why":"Statement asks for SHA256 of decoded message; candidate text was hashed.","score":score})
                report.setdefault("flag_wrapping_helpers",[]).append({"answer":h,"suggested_flag":cand,"source":source,"score":score,"why":"SHA256 answer wrapper."})
                sl46_trace(report,"SHA256 answer",f"sha256({v[:80]!r}) -> {cand}",score,artifact,cand)
    return len(out)
def sl46_cardan_score(s):
    s=str(s or "")
    low=s.lower()
    sc=sl43_text_quality(s) if "sl43_text_quality" in globals() else 0
    # The Cyber Sprint crypto sometimes asks for hash, so useful text can contain URL/path.
    if any(w in low for w in ["http","https","cyber","sprint","nksc","flag","secret","raktas","reikalingas","slaptas","message"]):
        sc+=180
    if re.search(r"[a-z0-9]{2,}_[a-z0-9_]{2,}",low):
        sc+=120
    if re.search(r"[a-z]{4,}\.[a-z]{2,}",low):
        sc+=80
    return sc
def sl46_parse_8x8_key_grid(text):
    rows=[]
    for line in str(text or "").splitlines():
        if line.startswith("|") and line.endswith("|") and len(line)>=10:
            inner=line[1:-1]
            if len(inner)==8:
                rows.append(inner)
    if len(rows)!=8:
        # fallback: lines of 8 chars containing key art chars
        rows=[x for x in str(text or "").splitlines() if len(x)==8 and re.fullmatch(r"[ .oO+=*#@%$xX-]{8}",x)]
    if len(rows)!=8:
        return None
    holes=[(r,c) for r,row in enumerate(rows) for c,ch in enumerate(row) if ch!=" "]
    if len(holes)!=16:
        return None
    # Ensure rotations cover all 64 cells for a valid grille; if not, still return as weak.
    return rows, holes
def sl46_rot(pos,k,n=8):
    r,c=pos
    for _ in range(k%4):
        r,c=c,n-1-r
    return r,c
def sl46_reflect(pos,mode,n=8):
    r,c=pos
    if mode=="none": return r,c
    if mode=="h": return r,n-1-c
    if mode=="v": return n-1-r,c
    if mode=="d": return c,r
    if mode=="a": return n-1-c,n-1-r
    return r,c
def sl46_cardan_candidates(cipher, key_text):
    cipher=re.sub(r"\s+","",str(cipher or ""))
    parsed=sl46_parse_8x8_key_grid(key_text)
    if not parsed or len(cipher)!=64:
        return []
    rows, holes=parsed
    grid=[list(cipher[i*8:(i+1)*8]) for i in range(8)]
    cands=[]
    modes=["none","h","v","d","a"]
    rot_orders=list(itertools.permutations([0,1,2,3]))
    for mode in modes:
        base=[sl46_reflect(h,mode) for h in holes]
        hole_orders=[
            ("key",base),
            ("key_rev",list(reversed(base))),
            ("row",sorted(base)),
            ("row_rev",list(reversed(sorted(base)))),
            ("col",sorted(base,key=lambda x:(x[1],x[0]))),
            ("col_rev",list(reversed(sorted(base,key=lambda x:(x[1],x[0]))))),
        ]
        for order_name,orderholes in hole_orders:
            for ro in rot_orders:
                posseq=[]
                for k in ro:
                    posseq += [sl46_rot(h,k) for h in orderholes]
                if len(posseq)!=64:
                    continue
                # Prefer valid cover, but keep invalid lower score if duplicate positions.
                cover_bonus=80 if len(set(posseq))==64 else -80
                pt="".join(grid[r][c] for r,c in posseq)
                for label,val in [("plain",pt),("reverse",pt[::-1])]:
                    sc=sl46_cardan_score(val)+cover_bonus
                    cands.append({"method":"cardan_read","mode":mode,"hole_order":order_name,"rotation_order":ro,"variant":label,"plaintext":val,"score":sc,"sha256":hashlib.sha256(val.encode()).hexdigest()})
                # Also try using cipher as filled through holes and reading row-wise.
                fill=[None]*64
                for ch,(r,c) in zip(cipher,posseq):
                    fill[r*8+c]=ch
                if all(x is not None for x in fill):
                    val="".join(fill)
                    sc=sl46_cardan_score(val)+cover_bonus
                    cands.append({"method":"cardan_fill","mode":mode,"hole_order":order_name,"rotation_order":ro,"variant":"row_read","plaintext":val,"score":sc,"sha256":hashlib.sha256(val.encode()).hexdigest()})
    out=[]; seen=set()
    for c in sorted(cands,key=lambda x:x["score"],reverse=True):
        k=c["plaintext"]
        if k not in seen:
            seen.add(k); out.append(c)
        if len(out)>=250: break
    return out
def sl46_message_key_pair_agent(report, root, data):
    """File-level helper when a text contains both message and key."""
    text=data[:400000].decode("utf-8","ignore")
    cipher_m=re.search(r"(?i)(?:pranešimą|pranesima|message)\s*[:=]\s*([A-Z0-9:./_\-]{16,200})",text)
    if not cipher_m:
        # fallback: longest 64-char allcaps/digit/punct token
        toks=re.findall(r"[A-Z0-9:./_\-]{64}",text)
        cipher=toks[0] if toks else ""
    else:
        cipher=cipher_m.group(1)
    if len(cipher)!=64 or not sl46_parse_8x8_key_grid(text):
        return []
    cands=sl46_cardan_candidates(cipher,text)
    if not cands:
        return []
    art=sl46_art(root,report,"cardan_grille_candidates.json",json.dumps(cands,indent=2,ensure_ascii=False),"sloper46_cardan_grille",300,"Cardan/Fleissner grille candidates from 8x8 key grid.")
    if art:
        for c in cands[:30]:
            sl45_promote_answer_markers(report,c["plaintext"],"SLOPER v46 Cardan",art.get("path"),260)
            if sl46_statement_wants_sha256(report):
                sl46_promote_sha256_answer(report,c["plaintext"],"SLOPER v46 Cardan SHA256",art.get("path"),310)
        return [art]
    return []
def sl46_project_message_key_agent(pid, reports, meta):
    """Project-level: pair message .txt and Raktas.txt key grid."""
    root=pdir(pid)
    files_dir=root/"files"
    texts=[]
    for p in files_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in [".txt",".log",".md"]:
            try:
                texts.append((p,p.read_text(encoding="utf-8",errors="ignore")))
            except Exception:
                pass
    cipher=""
    cipher_source=""
    key_text=""
    key_source=""
    for p,t in texts:
        m=re.search(r"(?i)(?:pranešimą|pranesima|message)\s*[:=]\s*([A-Z0-9:./_\-]{16,200})",t)
        if m and len(m.group(1))==64:
            cipher=m.group(1); cipher_source=str(p)
        elif not cipher:
            toks=re.findall(r"[A-Z0-9:./_\-]{64}",t)
            if toks:
                cipher=toks[0]; cipher_source=str(p)
        if sl46_parse_8x8_key_grid(t):
            key_text=t; key_source=str(p)
    if not cipher or not key_text:
        return reports
    # Attach results to the message report if possible, else first report.
    target=None
    for r in reports:
        if r.get("path")==cipher_source or Path(r.get("path","")).name.lower().startswith("prane"):
            target=r; break
    if target is None:
        target=reports[0] if reports else {"id":uuid.uuid4().hex[:10],"name":"project_cardan","path":"","rel":"","kind":"project","flags":[],"strings":[],"outputs":[],"artifacts":[],"transformations":[],"solve_trace":[],"agent_trace":[],"answer_candidates":[],"flag_wrapping_helpers":[]}
        if not reports: reports.append(target)
    cands=sl46_cardan_candidates(cipher,key_text)
    if not cands:
        return reports
    art=sl46_art(root,target,"project_cardan_grille_candidates.json",json.dumps({"cipher_source":cipher_source,"key_source":key_source,"candidates":cands},indent=2,ensure_ascii=False),"sloper46_project_cardan_grille",330,"Project-level Cardan/Fleissner grille candidates from message file plus key-grid file.")
    if art:
        for c in cands[:40]:
            sl45_promote_answer_markers(target,c["plaintext"],"SLOPER v46 Project Cardan",art.get("path"),270)
            if sl46_statement_wants_sha256(meta) or sl46_statement_wants_sha256(target):
                sl46_promote_sha256_answer(target,c["plaintext"],"SLOPER v46 Project Cardan SHA256",art.get("path"),330)
        try: sl_finalize_report(target)
        except Exception: pass
    return reports
def sl46_pcap_export_objects_agent(report, root, data):
    p=Path(report.get("path",""))
    if p.suffix.lower() not in [".pcap",".pcapng"] and report.get("kind")!="pcap":
        return []
    arts=[]
    if not exists("tshark"):
        return []
    outbase=root/"generated"/"sloper46"/safe(report.get("name","file"))/"pcap_export"
    outbase.mkdir(parents=True,exist_ok=True)
    for proto in ["http","smb","tftp"]:
        try:
            outdir=outbase/proto
            outdir.mkdir(parents=True,exist_ok=True)
            r=run(["tshark","-r",str(p),"--export-objects",f"{proto},{outdir}"],30)
            if any(x.is_file() for x in outdir.rglob("*")):
                logart=sl46_art(root,report,f"pcap_export_{proto}_log.txt",r.get("out",""),"sloper46_pcap_export_log",220,f"Exported {proto} objects with tshark.")
                if logart: arts.append(logart)
                for child in outdir.rglob("*"):
                    if child.is_file() and child.stat().st_size>0:
                        cart={"kind":"sloper46_pcap_exported_object","name":child.name,"path":str(child),"url":"/api/raw?path="+str(child),"source":"CTF SLOPER v46","score":290,"note":f"PCAP exported {proto} object.","exists":True,"size":child.stat().st_size,"file":report.get("rel","")}
                        report.setdefault("artifacts",[]).append(cart); report.setdefault("transformations",[]).append(cart); arts.append(cart)
                        raw=child.read_bytes()[:2_000_000]
                        txt=raw.decode("utf-8","ignore")
                        sl45_promote_answer_markers(report,txt,"SLOPER v46 PCAP exported object",str(child),310)
                        try: sf_embedded_compression_agent(report,root,raw)
                        except Exception: pass
        except Exception as e:
            sl46_trace(report,"PCAP export failed",f"{proto}: {e}",0)
    return arts
def sl46_run_agents(report, root, data):
    arts=[]
    try: arts += sl46_message_key_pair_agent(report,root,data)
    except Exception as e: sl46_trace(report,"message-key failed",str(e),0)
    try: arts += sl46_pcap_export_objects_agent(report,root,data)
    except Exception as e: sl46_trace(report,"pcap export failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v46 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v46(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl46_trace(report,"previous agents failed",str(e),0)
    try:
        arts += sl46_run_agents(report,root,data) or []
    except Exception as e:
        sl46_trace(report,"v46 agents failed",str(e),0)
    return arts
_prev_sl42_is_bad_wrapper_body_v46 = sl42_is_bad_wrapper_body
def sl42_is_bad_wrapper_body(body):
    b=str(body or "").strip().strip("{}")
    low=b.lower()
    placeholders=[
        "vietos_pavadinimas","rastos.vietos.pavadinimas","rastas_tekstas",
        "frazė+cwe_kodas","fraze+cwe_kodas","sha256_kodas","gatves_pavadinimas",
        "pastato_numeris","jūsų_atsakymas","jusu_atsakymas"
    ]
    if low in placeholders:
        return True
    if re.fullmatch(r"(vietos|rastos|rastas|tekstas|fraz[eė]|kodas|sha256|pavadinimas)[a-z0-9_.+-]*",low):
        return True
    return _prev_sl42_is_bad_wrapper_body_v46(body)
_prev_project_summary_v46 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v46(reports, meta)
    caps=summary.get("sloper45_capability_hits",{}) or {}
    caps["cardan_grille"]=0
    caps["pcap_exports"]=0
    caps["sha256_answers"]=0
    for a in summary.get("artifacts",[]):
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "cardan" in txt or "grille" in txt: caps["cardan_grille"]+=1
        if "pcap_export" in txt or "exported_object" in txt: caps["pcap_exports"]+=1
    for r in reports:
        for t in r.get("solve_trace",[])[:200]:
            if isinstance(t,dict) and "sha256" in str(t).lower():
                caps["sha256_answers"]+=1
    summary["sloper46_capability_hits"]=caps
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper46" in txt or "v46" in txt: s+=3800
        if "sloper45" in txt or "v45" in txt: s+=3000
        if any(k in txt for k in ["cardan","grille","sha256","pcap_export","exported_object"]): s+=900
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(summary.get("artifacts",[]),key=pri,reverse=True)[:3600]
    na=summary.get("sloper45_next_actions",[]) or summary.get("sloper44_next_actions",[]) or summary.get("workflow_steps",[]) or []
    if caps.get("cardan_grille"):
        na.insert(0,{"priority":97,"step":"Review v46 Cardan/Fleissner candidates.","why":"Project contains a 64-symbol message and 8x8 key grid."})
    if caps.get("pcap_exports"):
        na.insert(0,{"priority":96,"step":"Review v46 PCAP exported objects.","why":"Network capture yielded extracted objects/payloads."})
    summary["sloper46_next_actions"]=na[:26]
    summary["workflow_steps"]=na[:26]+summary.get("workflow_steps",[])[:20]
    return summary
_prev_analyze_project_v46 = analyze_project
def analyze_project(pid):
    _prev_analyze_project_v46(pid)
    try:
        root=pdir(pid); meta=jread(meta_path(pid),{})
        rep=jread(report_path(pid),{})
        reports=rep.get("files",[])
        reports=sl46_project_message_key_agent(pid,reports,meta)
        jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    except Exception as e:
        try: log(pid,f"v46 project cardan failed: {e}")
        except Exception: pass
APP_TITLE = "CTF SLOPER v46"
def sl46_find_project_message_key(root):
    files_dir=Path(root)/"files"
    texts=[]
    try:
        for p in files_dir.rglob("*"):
            if p.is_file() and p.suffix.lower() in [".txt",".log",".md"] and not sl45_is_internal_generated_file(p,root):
                try:
                    texts.append((p,p.read_text(encoding="utf-8",errors="ignore")))
                except Exception:
                    pass
    except Exception:
        return None
    cipher=""; cipher_source=None
    key_text=""; key_source=None
    statement_blob="\n".join(t for _,t in texts)
    for p,t in texts:
        m=re.search(r"(?i)(?:pranešimą|pranesima|message|radote pranešimą)\s*[:=]\s*([A-Z0-9:./_\-]{64})",t)
        if m:
            cipher=m.group(1); cipher_source=p
        elif not cipher:
            toks=re.findall(r"\b[A-Z0-9:./_\-]{64}\b",t)
            if toks:
                cipher=toks[0]; cipher_source=p
        if sl46_parse_8x8_key_grid(t):
            key_text=t; key_source=p
    if cipher and key_text:
        return {"cipher":cipher,"cipher_source":cipher_source,"key_text":key_text,"key_source":key_source,"statement":statement_blob}
    return None
def sl46_has_fast_message_key_project(root):
    return sl46_find_project_message_key(root) is not None
def sl46_fast_message_key_project(pid):
    root=pdir(pid); meta=jread(meta_path(pid),{})
    mk=sl46_find_project_message_key(root)
    reports=[]
    progress(pid,2,"v46 fast message-key crypto mode")
    if not mk:
        progress(pid,100,"Done")
        return
    cipher_source=mk["cipher_source"]
    key_source=mk["key_source"]
    # Create one synthetic project report attached to message file.
    p=Path(cipher_source)
    data=p.read_bytes()
    rel=str(p.relative_to(root)) if str(p).startswith(str(root)) else p.name
    report={
        "id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":rel,"kind":"text",
        "size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest(),"magic":data[:32].hex(),
        "flags":[],"weak_flag_candidates":[],"verified_flags":[],"verified_flags_visible":[],"strings":py_strings(data,limit=1200),"outputs":[],"previews":[],
        "commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"transformations":[],"findings":[],
        "next_steps":[],"solve_trace":[],"agent_trace":[],"answer_candidates":[],"flag_wrapping_helpers":[],"evidence_scored_candidates":[]
    }
    reports.append(report)
    # Also include key file as lightweight report for visibility.
    if key_source and Path(key_source)!=p:
        kp=Path(key_source); kd=kp.read_bytes()
        reports.append({
            "id":uuid.uuid4().hex[:10],"name":kp.name,"path":str(kp),"rel":str(kp.relative_to(root)) if str(kp).startswith(str(root)) else kp.name,"kind":"text",
            "size":len(kd),"sha256":hashlib.sha256(kd).hexdigest(),"md5":hashlib.md5(kd).hexdigest(),"magic":kd[:32].hex(),
            "flags":[],"weak_flag_candidates":[],"verified_flags":[],"verified_flags_visible":[],"strings":py_strings(kd,limit=800),"outputs":[],"previews":[],
            "commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"transformations":[],"findings":[],
            "next_steps":[],"solve_trace":[{"stage":"SLOPER v46 fast message-key","detail":"Used as Cardan/Fleissner key-grid file.","confidence":250,"artifact":str(kp),"flag":""}],"agent_trace":[],"answer_candidates":[],"flag_wrapping_helpers":[],"evidence_scored_candidates":[]
        })
    progress(pid,20,"v46 Cardan/Fleissner candidates")
    cands=sl46_cardan_candidates(mk["cipher"],mk["key_text"])
    art=sl46_art(root,report,"fast_project_cardan_grille_candidates.json",json.dumps({"cipher_source":str(cipher_source),"key_source":str(key_source),"candidates":cands},indent=2,ensure_ascii=False),"sloper46_fast_project_cardan",360,"Fast project Cardan/Fleissner candidates from message+key files.")
    if art:
        for c in cands[:60]:
            sl45_promote_answer_markers(report,c["plaintext"],"SLOPER v46 Fast Project Cardan",art.get("path"),270)
            if sl46_statement_wants_sha256(meta) or "sha256" in mk.get("statement","").lower():
                sl46_promote_sha256_answer(report,c["plaintext"],"SLOPER v46 Fast Project SHA256",art.get("path"),340)
        report["findings"].append({"score":360,"type":"sloper46_cardan_candidates","value":f"{len(cands)} candidates","why":"Generated Cardan/Fleissner plaintext and SHA256 answer candidates."})
        report["next_steps"].append({"priority":96,"step":"Review Cardan candidates and SHA256 wrappers.","why":"This task asks for SHA256 of a decoded message; multiple grille orientations were tested."})
    try: sl_finalize_report(report)
    except Exception: pass
    progress(pid,100,"Done")
    jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    with LOCK: JOBS.setdefault(pid,{})["status"]="done"
_prev_analyze_project_v46_fast_message_key = analyze_project
def analyze_project(pid):
    try:
        root=pdir(pid)
        if sl46_has_fast_message_key_project(root):
            return sl46_fast_message_key_project(pid)
    except Exception as e:
        try: log(pid,f"v46 fast message-key check failed: {e}")
        except Exception: pass
    return _prev_analyze_project_v46_fast_message_key(pid)
def sl46_cardan_candidates(cipher, key_text):
    import itertools, hashlib
    cipher=re.sub(r"\s+","",str(cipher or ""))
    parsed=sl46_parse_8x8_key_grid(key_text)
    if not parsed or len(cipher)!=64:
        return []
    rows, holes=parsed
    grid=[list(cipher[i*8:(i+1)*8]) for i in range(8)]
    cands=[]
    modes=["none","h","v","d","a"]
    rot_orders=list(itertools.permutations([0,1,2,3]))
    for mode in modes:
        base=[sl46_reflect(h,mode) for h in holes]
        hole_orders=[
            ("key",base),
            ("key_rev",list(reversed(base))),
            ("row",sorted(base)),
            ("row_rev",list(reversed(sorted(base)))),
            ("col",sorted(base,key=lambda x:(x[1],x[0]))),
            ("col_rev",list(reversed(sorted(base,key=lambda x:(x[1],x[0]))))),
        ]
        for order_name,orderholes in hole_orders:
            for ro in rot_orders:
                posseq=[]
                for k in ro:
                    posseq += [sl46_rot(h,k) for h in orderholes]
                if len(posseq)!=64:
                    continue
                cover_bonus=80 if len(set(posseq))==64 else -80
                pt="".join(grid[r][c] for r,c in posseq)
                for label,val in [("plain",pt),("reverse",pt[::-1])]:
                    sc=sl46_cardan_score(val)+cover_bonus
                    cands.append({"method":"cardan_read","mode":mode,"hole_order":order_name,"rotation_order":ro,"variant":label,"plaintext":val,"score":sc,"sha256":hashlib.sha256(val.encode()).hexdigest()})
                fill=[None]*64
                for ch,(r,c) in zip(cipher,posseq):
                    fill[r*8+c]=ch
                if all(x is not None for x in fill):
                    val="".join(fill)
                    sc=sl46_cardan_score(val)+cover_bonus
                    cands.append({"method":"cardan_fill","mode":mode,"hole_order":order_name,"rotation_order":ro,"variant":"row_read","plaintext":val,"score":sc,"sha256":hashlib.sha256(val.encode()).hexdigest()})
    out=[]; seen=set()
    for c in sorted(cands,key=lambda x:x["score"],reverse=True):
        k=c["plaintext"]
        if k not in seen:
            seen.add(k); out.append(c)
        if len(out)>=250: break
    return out
def analyze_project(pid):
    root=pdir(pid)
    if sl46_has_fast_message_key_project(root):
        # Do not silently fall back to heavy legacy if the fast pattern is detected.
        return sl46_fast_message_key_project(pid)
    return _prev_analyze_project_v46_fast_message_key(pid)
def sl46_promote_sha256_answer(report, text, source, artifact=None, score=330, promote=False):
    """Generate SHA256 answer candidates. Do not promote multiple hash guesses as flags by default."""
    text=str(text or "").strip()
    if not text:
        return 0
    variants=[]
    variants.append(text)
    if "\n" in text:
        lines=[x.strip() for x in text.splitlines() if x.strip()]
        variants += lines[:20]
    variants += [re.sub(r"(?i)^(decoded|message|pranešimas|pranesimas|answer|flag)\s*[:=]\s*","",v).strip() for v in variants]
    out=[]; seen=set()
    for v in variants:
        v=v.strip()
        if not v or len(v)>10000:
            continue
        for vv,label in [(v,"no_newline"),(v+"\n","with_newline")]:
            h=hashlib.sha256(vv.encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            cand=f"ctf_cs{{{h}}}"
            out.append({"input":v,"input_len":len(v),"newline":label,"sha256":h,"suggested_flag":cand})
            report.setdefault("answer_candidates",[]).append({"value":h,"source":source,"why":f"SHA256 candidate ({label}) of decoded message candidate. Review plaintext evidence before submitting.","score":score})
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":h,"suggested_flag":cand,"source":source,"score":score,"why":f"SHA256 candidate ({label}); not auto-promoted unless uniquely verified."})
            if promote:
                if cand not in report.setdefault("flags",[]):
                    report["flags"].append(cand)
                sl46_trace(report,"SHA256 answer promoted",f"sha256({v[:80]!r}, {label}) -> {cand}",score,artifact,cand)
            else:
                sl46_trace(report,"SHA256 candidate",f"sha256({v[:80]!r}, {label}) -> {cand}",score,artifact,"")
    # Store compact SHA candidate artifact next to Cardan artifact.
    try:
        if out:
            sl46_art(Path(artifact).parents[3] if artifact else Path(report.get("path","")).parents[1], report, "sha256_answer_candidates.json", json.dumps(out[:120],indent=2,ensure_ascii=False), "sloper46_sha256_candidates", score, "SHA256 candidates from decoded-message candidates; not auto-promoted.")
    except Exception:
        pass
    return len(out)
def sl46_finalize_report_demote_hash_flags(report):
    # Remove hash-only flags created by older calls when there are multiple hash guesses from v46.
    hash_flags=[f for f in report.get("flags",[]) if re.fullmatch(r"ctf_cs\{[0-9a-f]{64}\}",str(f or ""))]
    if len(hash_flags)>1:
        report["flags"]=[f for f in report.get("flags",[]) if f not in hash_flags]
        report.setdefault("next_steps",[]).insert(0,{"priority":97,"step":"Review SHA256 wrapper candidates instead of promoted flags.","why":"Multiple Cardan/Fleissner plaintext candidates exist, so SHA256 values are not auto-promoted."})
    return report
_prev_sl46_fast_message_key_project_demote = sl46_fast_message_key_project
def sl46_fast_message_key_project(pid):
    _prev_sl46_fast_message_key_project_demote(pid)
    try:
        root=pdir(pid); meta=jread(meta_path(pid),{})
        rep=jread(report_path(pid),{})
        reports=rep.get("files",[])
        for r in reports:
            sl46_finalize_report_demote_hash_flags(r)
            try: sl_finalize_report(r)
            except Exception: pass
            sl46_finalize_report_demote_hash_flags(r)
        jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    except Exception as e:
        try: log(pid,f"v46 hash demotion failed: {e}")
        except Exception: pass
def sl46_add_sha256_wrappers_only(report, cands, source, artifact=None, score=330, limit=80):
    seen=set(); out=[]
    for c in cands[:limit]:
        txt=str(c.get("plaintext","")).strip()
        if not txt: continue
        variants=[(txt,"no_newline"),(txt+"\n","with_newline")]
        for v,label in variants:
            h=hashlib.sha256(v.encode()).hexdigest()
            if h in seen: continue
            seen.add(h)
            flag=f"ctf_cs{{{h}}}"
            out.append({"plaintext":txt,"method":c.get("method"),"mode":c.get("mode"),"hole_order":c.get("hole_order"),"rotation_order":c.get("rotation_order"),"variant":c.get("variant"),"newline":label,"sha256":h,"suggested_flag":flag,"score":c.get("score",0)})
            report.setdefault("answer_candidates",[]).append({"value":h,"source":source,"why":f"SHA256 candidate ({label}) from Cardan/Fleissner plaintext candidate. Not auto-promoted because multiple grille orientations exist.","score":score})
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":h,"suggested_flag":flag,"source":source,"score":score,"why":f"SHA256 candidate ({label}); review Cardan plaintext first."})
    return out
def sl46_fast_message_key_project(pid):
    root=pdir(pid); meta=jread(meta_path(pid),{})
    mk=sl46_find_project_message_key(root)
    reports=[]
    progress(pid,2,"v46 lightweight message-key crypto mode")
    if not mk:
        jwrite(report_path(pid),{"project":meta,"files":[],"summary":project_summary([],meta),"ai_prompt":"","updated":now()})
        progress(pid,100,"Done")
        with LOCK: JOBS.setdefault(pid,{})["status"]="done"
        return
    p=Path(mk["cipher_source"])
    data=p.read_bytes()
    rel=str(p.relative_to(root)) if str(p).startswith(str(root)) else p.name
    report={
        "id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":rel,"kind":"text",
        "size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest(),"magic":data[:32].hex(),
        "flags":[],"weak_flag_candidates":[],"verified_flags":[],"verified_flags_visible":[],"strings":py_strings(data,limit=1200),"outputs":[],"previews":[],
        "commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"transformations":[],"findings":[],
        "next_steps":[],"solve_trace":[],"agent_trace":[],"answer_candidates":[],"flag_wrapping_helpers":[],"evidence_scored_candidates":[]
    }
    reports.append(report)
    if mk.get("key_source") and Path(mk["key_source"])!=p:
        kp=Path(mk["key_source"]); kd=kp.read_bytes()
        reports.append({
            "id":uuid.uuid4().hex[:10],"name":kp.name,"path":str(kp),"rel":str(kp.relative_to(root)) if str(kp).startswith(str(root)) else kp.name,"kind":"text",
            "size":len(kd),"sha256":hashlib.sha256(kd).hexdigest(),"md5":hashlib.md5(kd).hexdigest(),"magic":kd[:32].hex(),
            "flags":[],"weak_flag_candidates":[],"verified_flags":[],"verified_flags_visible":[],"strings":py_strings(kd,limit=800),"outputs":[],"previews":[],
            "commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"transformations":[],"findings":[],
            "next_steps":[],"solve_trace":[{"stage":"SLOPER v46 fast message-key","detail":"Used as Cardan/Fleissner key-grid file.","confidence":250,"artifact":str(kp),"flag":""}],"agent_trace":[],"answer_candidates":[],"flag_wrapping_helpers":[],"evidence_scored_candidates":[]
        })
    progress(pid,25,"v46 Cardan/Fleissner candidates")
    cands=sl46_cardan_candidates(mk["cipher"],mk["key_text"])
    art=sl46_art(root,report,"fast_project_cardan_grille_candidates.json",json.dumps({"cipher_source":str(mk["cipher_source"]),"key_source":str(mk["key_source"]),"candidates":cands},indent=2,ensure_ascii=False),"sloper46_fast_project_cardan",360,"Fast project Cardan/Fleissner candidates from message+key files.")
    if art:
        # Only exact ctf_cs/FLAG markers can become flags; SHA hashes remain wrapper candidates.
        for c in cands[:80]:
            sl45_promote_answer_markers(report,c["plaintext"],"SLOPER v46 Fast Project Cardan",art.get("path"),270)
        sha_out=[]
        if sl46_statement_wants_sha256(meta) or "sha256" in mk.get("statement","").lower():
            sha_out=sl46_add_sha256_wrappers_only(report,cands,"SLOPER v46 Fast Project SHA256",art.get("path"),340,limit=80)
            sl46_art(root,report,"sha256_answer_candidates.json",json.dumps(sha_out,indent=2,ensure_ascii=False),"sloper46_sha256_candidates",340,"SHA256 candidates from Cardan plaintext candidates. These are wrappers, not promoted flags.")
        report["findings"].append({"score":360,"type":"sloper46_cardan_candidates","value":f"{len(cands)} candidates","why":"Generated Cardan/Fleissner plaintext candidates and SHA256 wrapper candidates."})
        report["next_steps"].append({"priority":97,"step":"Open fast_project_cardan_grille_candidates.json and choose the readable plaintext.","why":"The task asks for SHA256 of decoded text. Multiple Cardan orientations are possible, so hashes are shown as wrapper candidates, not promoted flags."})
        report["solve_trace"].append({"stage":"SLOPER v46 fast Cardan","detail":f"Generated {len(cands)} Cardan candidates and {len(sha_out)} SHA256 wrapper candidates.","confidence":330,"artifact":art.get("path"),"flag":""})
    progress(pid,90,"summary")
    jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    progress(pid,100,"Done")
    with LOCK: JOBS.setdefault(pid,{})["status"]="done"
def sl46_add_sha256_wrappers_only(report, cands, source, artifact=None, score=330, limit=15):
    seen=set(); out=[]
    for c in cands[:limit]:
        txt=str(c.get("plaintext","")).strip()
        if not txt:
            continue
        variants=[(txt,"no_newline"),(txt+"\n","with_newline")]
        for v,label in variants:
            h=hashlib.sha256(v.encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            flag=f"ctf_cs{{{h}}}"
            out.append({"plaintext":txt,"method":c.get("method"),"mode":c.get("mode"),"hole_order":c.get("hole_order"),"rotation_order":c.get("rotation_order"),"variant":c.get("variant"),"newline":label,"sha256":h,"suggested_flag":flag,"score":c.get("score",0)})
            report.setdefault("answer_candidates",[]).append({"value":h,"source":source,"why":f"Top Cardan SHA256 candidate ({label}). Not auto-promoted because several grille orientations exist.","score":score})
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":h,"suggested_flag":flag,"source":source,"score":score,"why":f"Top Cardan SHA256 candidate ({label}); review plaintext evidence first."})
    return out
def sl46_add_sha256_wrappers_only(report, cands, source, artifact=None, score=330, limit=15):
    limit=min(int(limit or 15),15)
    seen=set(); out=[]
    for c in cands[:limit]:
        txt=str(c.get("plaintext","")).strip()
        if not txt:
            continue
        for v,label in [(txt,"no_newline"),(txt+"\n","with_newline")]:
            h=hashlib.sha256(v.encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            flag=f"ctf_cs{{{h}}}"
            out.append({"plaintext":txt,"method":c.get("method"),"mode":c.get("mode"),"hole_order":c.get("hole_order"),"rotation_order":c.get("rotation_order"),"variant":c.get("variant"),"newline":label,"sha256":h,"suggested_flag":flag,"score":c.get("score",0)})
            report.setdefault("answer_candidates",[]).append({"value":h,"source":source,"why":f"Top-{limit} Cardan SHA256 candidate ({label}). Not auto-promoted because several grille orientations exist.","score":score})
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":h,"suggested_flag":flag,"source":source,"score":score,"why":f"Top-{limit} Cardan SHA256 candidate ({label}); review plaintext evidence first."})
    return out
def sl47_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl46_trace(report, "v47:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v47:"+str(stage),
            "detail":str(detail)[:1300],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl47_art(root, report, name, content, kind="sloper47_artifact", score=180, note=""):
    outdir=root/"generated"/"sloper47"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v47","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl47_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl47_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl47_fast_extract_clue_values_nochain(text):
    vals=[]
    text=str(text or "")
    label_re=r"(?:password|pass|pwd|key|raktas|slaptažodis|slaptazodis|secret|token|code|kodas|comment|komentaras|flag|answer|atsakymas)\s*[:=]\s*['\"]?([A-Za-z0-9_\-+.@:/=]{3,180})"
    for m in re.finditer(label_re,text[:220000],re.I):
        vals.append({"value":m.group(1).strip("'\""),"source":"label","score":180})
    for m in re.finditer(r"\{([A-Za-z0-9_\-:.+]{4,180})\}",text[:220000]):
        vals.append({"value":m.group(1),"source":"braced_body","score":210})
    for line in text[:220000].splitlines():
        if re.fullmatch(r"[.\-/\s]{8,}",line.strip()) and "." in line and "-" in line:
            try:
                dec=sl42_decode_morse(line)
                if dec:
                    vals.append({"value":dec.strip().replace(" ","_"),"source":"morse","score":190})
            except Exception:
                pass
    out=[]; seen=set()
    for v in vals:
        val=str(v.get("value","")).strip()
        if 3<=len(val)<=180 and val.lower() not in seen:
            seen.add(val.lower()); out.append(v)
    return out[:120]
_prev_sl42_extract_clue_values_v47 = sl42_extract_clue_values
def sl42_extract_clue_values(text):
    # Old implementation recursively decode-chained huge blobs and could hang summary.
    text=str(text or "")
    if len(text)>160000:
        return sl47_fast_extract_clue_values_nochain(text)
    return _prev_sl42_extract_clue_values_v47(text)
_prev_sl42_report_text_blob_v47 = sl42_report_text_blob
def sl42_report_text_blob(report, max_bytes=160000):
    # Bounded version: enough for clues, not enough to stall UI summary.
    parts=[]
    try:
        parts += [str(x)[:4000] for x in report.get("strings",[])[:120]]
        for o in report.get("outputs",[])[:24]:
            parts.append((o.get("out") or "")[:12000])
        for c in report.get("chain_results",[])[:30]:
            parts.append((c.get("output") or "")[:12000])
        for a in report.get("artifacts",[])[:40]:
            p=Path(a.get("path",""))
            try:
                if p.exists() and p.is_file() and p.stat().st_size<max_bytes:
                    parts.append(p.read_bytes()[:max_bytes].decode("utf-8","ignore"))
            except Exception:
                pass
    except Exception:
        try:
            return _prev_sl42_report_text_blob_v47(report, max_bytes=80000)[:200000]
        except Exception:
            return ""
    return "\n".join(x for x in parts if x)[:450000]
def sl47_is_artifact_json_log(text):
    sample=str(text or "")[:8000]
    return '"x"' in sample and '"y"' in sample and '"rows"' in sample and sample.count("{")>=3
