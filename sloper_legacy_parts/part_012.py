# Auto-split from sloper_legacy_monolith.py lines 10540-...
def sf_pyc_backdoor_agent(report, root, data):
    if Path(report.get("path","")).suffix.lower()!=".pyc":
        return []
    arts=[]
    try:
        arts += cs_pyc_decode_artifacts(root,report,data)
    except Exception:
        pass
    joined="\n".join(report.get("strings",[])[:1000])+"\n"+"\n".join((a.get("name","")+" "+a.get("note","")) for a in report.get("artifacts",[])[:200])
    # Read pyc constants artifacts.
    for a in report.get("artifacts",[])[:200]:
        p=Path(a.get("path",""))
        try:
            if p.exists() and p.stat().st_size<800000:
                joined += "\n"+p.read_bytes()[:50000].decode("utf-8","ignore")
        except Exception: pass
    cwe=[]
    for m in re.finditer(r"\bCWE[-_ ]?(\d{2,4})\b",joined,re.I):
        cwe.append("CWE-"+m.group(1))
    phrases=[]
    for m in re.finditer(r"(?:backdoor|secret|password|admin|auth|login|phrase|fraz[eė])\s*[:=]\s*['\"]?([A-Za-z0-9_\-+. ]{4,80})",joined,re.I):
        phrases.append(m.group(1).strip().replace(" ","_"))
    if cwe or phrases:
        obj={"cwe":list(dict.fromkeys(cwe)),"phrases":list(dict.fromkeys(phrases))}
        art=sf_art(root,report,"pyc_backdoor_clues.json",json.dumps(obj,indent=2,ensure_ascii=False),"sprintforge_pyc_backdoor_clues",190,"CWE/phrase clues extracted from PYC constants.")
        for ph in obj["phrases"][:6]:
            for code in obj["cwe"][:6] or [""]:
                body=(ph+"+"+code) if code else ph
                sf_add_body_candidate(report,body,"SprintForge PycBackdoor", "phrase + CWE candidate from pyc constants",230,False,art.get("path") if art else "")
        return [art] if art else []
    return arts
def sf_pcap_advanced_agent(report, root, data):
    if report.get("kind")!="pcap" and Path(report.get("path","")).suffix.lower() not in [".pcap",".pcapng"]:
        return []
    arts=[]
    try: arts += cs_pcap_scalar_artifacts(root,report,data)
    except Exception: pass
    p=Path(report.get("path",""))
    # Try tshark field extractions if available.
    if exists("tshark"):
        filters=[
            ("dns_queries",["tshark","-r",str(p),"-Y","dns","-T","fields","-e","dns.qry.name"]),
            ("http_uris",["tshark","-r",str(p),"-Y","http","-T","fields","-e","http.host","-e","http.request.uri","-e","http.cookie"]),
            ("tcp_payload_hex",["tshark","-r",str(p),"-Y","tcp.len>0","-T","fields","-e","tcp.payload"]),
            ("icmp_data",["tshark","-r",str(p),"-Y","icmp","-T","fields","-e","data.data"]),
        ]
        for name,cmd in filters:
            try:
                r=run(cmd,18)
                out=r.get("out","")[:300000]
                report.setdefault("outputs",[]).append({"tool":"sprintforge_"+name,"ok":r.get("ok"),"cmd":r.get("cmd"),"out":out[:60000]})
                if out.strip():
                    art=sf_art(root,report,f"pcap_{name}.txt",out,"sprintforge_pcap_extraction",160,f"tshark {name} extraction.")
                    if art: arts.append(art)
                    # Decode hex payload lines
                    if name.endswith("hex") or name=="icmp_data":
                        joined=""
                        for line in out.splitlines()[:2000]:
                            hx=re.sub(r"[^0-9a-fA-F]","",line)
                            if len(hx)>=2 and len(hx)%2==0:
                                try: joined+=bytes.fromhex(hx).decode("utf-8","ignore")+"\n"
                                except Exception: pass
                        if joined:
                            txtart=sf_art(root,report,f"pcap_{name}_ascii.txt",joined,"sprintforge_pcap_payload_ascii",190,"Decoded hex payload bytes as ASCII.")
                            sf_promote_from_text(report,joined,"SprintForge PcapAgent","decoded pcap payload",txtart.get("path") if txtart else "",230)
                    else:
                        sf_promote_from_text(report,out,"SprintForge PcapAgent",name,art.get("path") if art else "",190)
            except Exception:
                pass
    if arts:
        sf_trace(report,"PcapAgent",f"{len(arts)} pcap extraction artifacts",180,arts[0].get("path"))
    return arts
def sf_audio_image_combo_agent(report, root, data):
    p=Path(report.get("path",""))
    arts=[]
    if p.suffix.lower()==".wav":
        try: arts += msf_audio_agent(report,root,p,data,data[:200000].decode("utf-8","ignore"))
        except Exception: pass
        # Also try spectrogram already available maybe.
    if report.get("kind")=="image" or p.suffix.lower() in [".png",".jpg",".jpeg",".bmp",".gif",".webp"]:
        try: arts += sf_tail_embedded_agent(report,root,data)
        except Exception: pass
        # Existing writeup image agents: Piet/tile/LSB/QR
        try: wf_writeup_agents(report,root,data)
        except Exception: pass
        try:
            if "qr" in ux_statement_text(report).lower() or len(data)<800000:
                arts += msf_qr_checkerboard_agent(report,root,p)
        except Exception: pass
    return arts
def sf_general_text_agent(report, root, data):
    text=data[:300000].decode("utf-8","ignore")
    arts=[]
    if not text.strip():
        return []
    # basic decoder chain is still useful.
    try:
        af_run_text_decoders(report,root,text,"SprintForge text",1000)
    except Exception:
        pass
    # transposition if statement hints or text is compact/random.
    hints=(ux_statement_text(report)+"\n"+text[:1000]).lower()
    if any(k in hints for k in ["transpozic", "teisinga tvarka", "išdėstyti", "isdestyti", "route", "rail", "column", "matrix", "matrica"]):
        try: arts += sf_transposition_agent(report,root,text)
        except Exception as e: sf_trace(report,"TranspositionAgent failed",str(e),0)
    # randomart key extraction
    if "[key]" in hints or "+-[key]" in text:
        try: arts += sf_key_text_agent(report,root,text)
        except Exception: pass
    # what3words-like OSINT clue just make artifact, do not claim solve
    if "///" in text:
        coords=re.findall(r"///[A-Za-z0-9_.-]+",text)
        if coords:
            art=sf_art(root,report,"what3words_or_location_clues.json",json.dumps({"clues":coords},indent=2,ensure_ascii=False),"sprintforge_location_clues",95,"Location/what3words-like clues; web/OSINT may need manual lookup.")
            if art: arts.append(art)
    return arts
def sf_route_file_agents(report, root, data):
    p=Path(report.get("path",""))
    kind=report.get("kind","generic")
    text=data[:300000].decode("utf-8","ignore")
    arts=[]
    route=(kind+" "+p.suffix.lower()+" "+p.name.lower()+" "+ux_statement_text(report).lower()+" "+text[:1500].lower())
    sf_trace(report,"Route",f"kind={kind} suffix={p.suffix.lower()} name={p.name}",60)
    # Always promote direct strict flags from text/strings.
    sf_promote_from_text(report,text+"\n"+"\n".join(report.get("strings",[])[:800]),"SprintForge DirectScan","direct ctf_cs scan",None,260)
    # Route by file type/category.
    if kind=="text" or p.suffix.lower() in [".txt",".log",".json",".csv",".md"]:
        arts += sf_general_text_agent(report,root,data)
    if kind=="image" or p.suffix.lower() in [".png",".jpg",".jpeg",".bmp",".gif",".webp"]:
        arts += sf_audio_image_combo_agent(report,root,data)
    if p.suffix.lower()==".wav":
        arts += sf_audio_image_combo_agent(report,root,data)
    if kind=="pcap" or p.suffix.lower() in [".pcap",".pcapng"]:
        arts += sf_pcap_advanced_agent(report,root,data)
    if kind=="archive" or p.suffix.lower() in [".zip",".gz",".tgz",".tar",".xz",".bz2",".zst",".zstd",".7z",".rar",".sb3"] or data[:4] in [b"PK\x03\x04", b"\x28\xb5\x2f\xfd", b"\x1f\x8b\x08"]:
        arts += sf_nested_archive_agent(report,root,data)
    if p.suffix.lower()==".pyc":
        arts += sf_pyc_backdoor_agent(report,root,data)
    # raw image/disk/file carving
    if p.suffix.lower() in [".dd",".img",".bin",".gz"] or "usb" in p.name.lower() or "evidence" in p.name.lower() or "disk" in route:
        # If gz raw, decompress then carve too.
        raw=data
        try:
            if data[:3]==b"\x1f\x8b\x08":
                import gzip as _gzip
                raw=_gzip.decompress(data)
                gzart=sf_art(root,report,"gzip_decompressed_raw.bin",raw,"sprintforge_gzip_raw",155,"Gzip decompressed raw image bytes.")
                if gzart: arts.append(gzart)
        except Exception:
            raw=data
        arts += sf_docx_carve_agent(report,root,raw)
        try: arts += sf_nested_archive_agent(report,root,raw)
        except Exception: pass
    # Reverse/binary already handled by v39 fast path; still run pyc/backdoor where needed.
    if report.get("kind") in ["binary","python_bytecode"] or p.suffix.lower() in [".exe",".elf",".so",".dll",".bin"]:
        try:
            arts += rf_reverse_immediate_agent(report,root,data,text)
        except Exception: pass
        if any(k in route for k in ["numeric","drebėj","drebej","coefficient","double","float","table","lentel"]):
            try: arts += wf_scan_numeric_tables(data,root,report)
            except Exception: pass
    # Final candidates.
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: report["flag_wrapping_helpers"]=[]
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    return arts
_prev_vf_postprocess_v40 = vf_postprocess
def vf_postprocess(report, root):
    report=_prev_vf_postprocess_v40(report, root)
    data=b""
    try: data=Path(report.get("path","")).read_bytes()[:80_000_000]
    except Exception: pass
    try:
        sf_route_file_agents(report,root,data)
    except Exception as e:
        sf_trace(report,"SprintForge failed",str(e),0)
    # final evidence-backed ctf_cs promotion.
    promoted=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        if wf_flag_has_solve_evidence(report,f):
            promoted.append(f)
    # preserve strong wrapper suggestions as candidates but not solved unless evidence exact/braced decode.
    report["flags"]=promoted[:20]
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: pass
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    return report
_prev_rf_fast_binary_analyze_file_v40 = rf_fast_binary_analyze_file
def rf_fast_binary_analyze_file(pid, path, root, i, total):
    report=_prev_rf_fast_binary_analyze_file_v40(pid,path,root,i,total)
    try:
        p=Path(path); data=p.read_bytes()[:20_000_000]
        # Run numeric table only for explicitly hinted analyzer tasks.
        hint=(ux_statement_text(report)+" "+p.name+" "+" ".join(report.get("strings",[])[:80])).lower()
        if any(k in hint for k in ["numeric","drebėj","drebej","coefficient","coeff","double","float","table","lentel"]):
            wf_scan_numeric_tables(data,root,report)
    except Exception:
        pass
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: pass
    return report
_prev_project_summary_v40 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v40(reports, meta)
    # Prioritize SprintForge artifacts.
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sprintforge" in txt: s+=900
        if any(k in txt for k in ["docx","pcap","transposition","tail","pyc","randomart","carved","route"]): s+=250
        if "reverseforge" in txt: s+=500
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(summary.get("artifacts",[]),key=pri,reverse=True)[:1800]
    # Add a practical status lane.
    if summary.get("flags"):
        summary.setdefault("workflow_steps",[]).insert(0,{"priority":100,"step":"Check top ctf_cs flag(s).","why":"SprintForge found evidence-backed primary-format flag(s)."})
    elif summary.get("flag_wrapping_helpers"):
        summary.setdefault("workflow_steps",[]).insert(0,{"priority":98,"step":"Review Wrapper Hints.","why":"Solver found likely body text but not enough evidence to promote automatically."})
    else:
        summary.setdefault("workflow_steps",[]).insert(0,{"priority":90,"step":"Review SprintForge artifacts.","why":"No promoted flag; inspect transformed/carved/decoded outputs."})
    return summary
def sf_static_zip_quickscan(zip_path="/mnt/data/Cyber Sprint 2026 1 etapas.zip", max_files=80):
    zip_path=Path(zip_path)
    if not zip_path.exists():
        return {"ok":False,"error":"zip not found","path":str(zip_path)}
    tmp=BASE/"generated"/"sprintforge_zip_quickscan"
    if tmp.exists(): shutil.rmtree(tmp,ignore_errors=True)
    tmp.mkdir(parents=True,exist_ok=True)
    results=[]
    with zipfile.ZipFile(zip_path) as z:
        names=[n for n in z.namelist() if not n.endswith("/")][:max_files]
        for name in names:
            data=z.read(name)
            rel=Path(name).name
            fake=tmp/safe("_".join(Path(name).parts[-3:]))
            fake.parent.mkdir(parents=True,exist_ok=True)
            fake.write_bytes(data)
            kind="text" if fake.suffix.lower() in [".txt",".log",".json"] else ("image" if fake.suffix.lower() in [".png",".jpg",".jpeg"] else ("pcap" if fake.suffix.lower() in [".pcap",".pcapng"] else "generic"))
            rep={"name":rel,"rel":rel,"path":str(fake),"kind":kind,"artifacts":[],"transformations":[],"flags":[],"strings":py_strings(data,limit=800),"outputs":[],"chain_results":[],"answer_candidates":[],"flag_wrapping_helpers":[],"solve_trace":[],"agent_trace":[]}
            try: sf_route_file_agents(rep,tmp,data)
            except Exception as e: rep["error"]=str(e)
            results.append({"file":name,"flags":rep.get("flags",[]),"answers":[a.get("value") for a in rep.get("answer_candidates",[])[:8]],"wrappers":[w.get("suggested_flag") for w in rep.get("flag_wrapping_helpers",[])[:5]],"artifacts":[a.get("kind") for a in rep.get("artifacts",[])[:8]],"trace":[t.get("stage") for t in rep.get("solve_trace",[])[:8]]})
    return {"ok":True,"zip":str(zip_path),"files":len(results),"results":results}
def sprintforge_quickscan(path:str="/mnt/data/Cyber Sprint 2026 1 etapas.zip"):
    try:
        return sf_static_zip_quickscan(path)
    except Exception as e:
        return {"ok":False,"error":str(e)}
def sf_text_score(text):
    s=str(text or "")
    if not s: return 0
    low=s.lower()
    printable=sum(1 for c in s if 32<=ord(c)<127 or c in "\n\r\t")
    score=int(80*printable/max(1,len(s)))
    if vf_primary_flags(s,limit=3,scan_limit=5000): score+=360
    if re.search(r"\{[A-Za-z0-9_\-:.+]{4,120}\}",s): score+=260
    if re.search(r"[a-z0-9]{3,}_[a-z0-9_]{2,}",low): score+=120
    if any(w in low for w in ["flag","secret","raktas","slapta","calc","you","route","test","admin","password","token","vilnius","lietuva","cwe"]): score+=55
    if len(s)>=8: score+=25
    if len(s)>600: score-=30
    if "�" in s: score-=70
    return score
def sf_transposition_agent(report, root, text):
    raw=str(text or "")
    lines=[x.strip() for x in raw.splitlines() if len(x.strip())>=6]
    cands=[]
    for line in lines:
        candidate=line
        if ":" in candidate and len(candidate.split(":",1)[1])>=6:
            candidate=candidate.split(":",1)[1].strip()
        if 6<=len(candidate)<=700:
            cands.append(candidate)
    if not cands: return []
    outs=[]
    for s in cands[:12]:
        L=len(s)
        factors=[]
        for r in range(1,min(60,L)+1):
            if L%r==0:
                c=L//r
                if 1<=c<=100:
                    factors.append((r,c))
        for r,c in factors[:160]:
            for name,out in sf_route_variants(s,r,c):
                for nm,txt in [(name,out),(name+"_rev",out[::-1])]:
                    sc=sf_text_score(txt)
                    if sc>=135 or re.search(r"\{[A-Za-z0-9_\-:.+]{4,120}\}",txt):
                        outs.append({"method":nm,"rows":r,"cols":c,"output":txt,"score":sc,"flags":vf_primary_flags(txt,limit=10,scan_limit=5000)})
    best=[]; seen=set()
    for x in sorted(outs,key=lambda y:y.get("score",0),reverse=True):
        k=x["output"][:180]
        if k not in seen:
            seen.add(k); best.append(x)
        if len(best)>=160: break
    if not best: return []
    art=sf_art(root,report,"transposition_route_candidates.json",json.dumps(best,indent=2,ensure_ascii=False),"sprintforge_transposition_candidates",195,"Route/column/grille transposition candidates from text.")
    for x in best[:50]:
        sf_promote_from_text(report,x.get("output",""),"SprintForge TranspositionAgent",f"{x.get('method')} {x.get('rows')}x{x.get('cols')}",art.get("path") if art else "",max(240,x.get("score",0)+60))
    sf_trace(report,"TranspositionAgent",f"{len(best)} route/transposition candidates",190,art.get("path") if art else "")
    return [art] if art else []
def rf_fast_binary_analyze_file(pid, path, root, i, total):
    """v40 truly minimal fast binary path. Avoids old stacked wrappers."""
    p=Path(path)
    data=p.read_bytes()
    rel=str(p.relative_to(root)) if str(p).startswith(str(root)) else p.name
    report={
        "id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":rel,"kind":"binary",
        "size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest(),"magic":data[:32].hex(),
        "flags":[],"weak_flag_candidates":[],"verified_flags":[],"verified_flags_visible":[],"strings":[],"outputs":[],"previews":[],
        "commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"transformations":[],"findings":[],
        "next_steps":[],"solve_trace":[],"agent_trace":[],"answer_candidates":[],"flag_wrapping_helpers":[],"evidence_scored_candidates":[]
    }
    try: report["strings"]=py_strings(data,limit=2200)
    except Exception: report["strings"]=[]
    # quick metadata only
    for tool,cmd,timeout in [
        ("file",["file",str(p)],3),
        ("readelf_header",["readelf","-h",str(p)],4),
        ("objdump_rodata",["objdump","-s","-j",".rodata",str(p)],5),
    ]:
        try:
            if exists(cmd[0]):
                r=run(cmd,timeout)
                report["outputs"].append({"tool":tool,"ok":r.get("ok"),"cmd":r.get("cmd"),"out":r.get("out","")[:40000]})
        except Exception:
            pass
    # Direct ctf_cs in strings.
    for f in vf_primary_flags("\n".join(report["strings"]),limit=30,scan_limit=80000):
        if f not in report["flags"]: report["flags"].append(f)
    # Reverse immediate path.
    try: rf_reverse_immediate_agent(report,root,data,data[:200000].decode("utf-8","ignore"))
    except Exception as e:
        try: msf_trace(report,"ReverseImmediateAgent failed",str(e),0)
        except Exception: pass
    # Only explicit numeric-table hint.
    hint=(ux_statement_text(report)+" "+p.name+" "+" ".join(report.get("strings",[])[:80])).lower()
    if any(k in hint for k in ["numeric","drebėj","drebej","coefficient","coeff","double","float","table","lentel"]):
        try: wf_scan_numeric_tables(data,root,report)
        except Exception: pass
    # Final strict promotion.
    promoted=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        if wf_flag_has_solve_evidence(report,f):
            promoted.append(f)
    promoted=sorted(list(dict.fromkeys(promoted)), key=lambda f: rf_flag_priority_score(f) if "rf_flag_priority_score" in globals() else 0, reverse=True)[:3]
    report["flags"]=promoted
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: report["flag_wrapping_helpers"]=[]
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    if report["flags"]:
        report["findings"].append({"score":520,"type":"reverseforge_flag","value":report["flags"][0],"why":"Fast binary ReverseForge path recovered high-confidence evidence-backed ctf_cs flag."})
    else:
        report["next_steps"].append({"priority":95,"step":"Open ReverseForge artifacts / solve trace.","why":"Binary was processed with static immediate deobfuscation."})
    return report
def rf_extract_x86_stack_immediates_from_bytes(data):
    """Fast direct scanner for common x86-64 stack immediate arrays:
    c7 45 xx imm32  -> mov DWORD PTR [rbp+disp8], imm32
    c6 45 xx imm8   -> mov BYTE PTR [rbp+disp8], imm8
    c7 85 disp32 imm32 -> mov DWORD PTR [rbp+disp32], imm32
    c6 85 disp32 imm8  -> mov BYTE PTR [rbp+disp32], imm8
    """
    b=bytes(data or b"")
    writes=[]
    i=0
    L=len(b)
    while i<L-7:
        # c7 45 disp imm32
        if b[i]==0xC7 and b[i+1]==0x45 and i+7<=L:
            disp=int.from_bytes(b[i+2:i+3],"little",signed=True)
            imm=int.from_bytes(b[i+3:i+7],"little",signed=False)
            if 0<=imm<=0xff:
                writes.append({"off":disp,"value":imm,"pos":i,"size":4})
                i+=7; continue
        # c6 45 disp imm8
        if b[i]==0xC6 and b[i+1]==0x45 and i+4<=L:
            disp=int.from_bytes(b[i+2:i+3],"little",signed=True)
            imm=b[i+3]
            writes.append({"off":disp,"value":imm,"pos":i,"size":1})
            i+=4; continue
        # c7 85 disp32 imm32
        if b[i]==0xC7 and b[i+1]==0x85 and i+10<=L:
            disp=int.from_bytes(b[i+2:i+6],"little",signed=True)
            imm=int.from_bytes(b[i+6:i+10],"little",signed=False)
            if 0<=imm<=0xff:
                writes.append({"off":disp,"value":imm,"pos":i,"size":4})
                i+=10; continue
        # c6 85 disp32 imm8
        if b[i]==0xC6 and b[i+1]==0x85 and i+7<=L:
            disp=int.from_bytes(b[i+2:i+6],"little",signed=True)
            imm=b[i+6]
            writes.append({"off":disp,"value":imm,"pos":i,"size":1})
            i+=7; continue
        i+=1
    if len(writes)<4:
        return []
    arrays=[]
    # Group contiguous stack offsets by 1/2/4/8. Keep original order and offset order.
    for ordering,ws in [("offset",sorted(writes,key=lambda x:x["off"])),("program",sorted(writes,key=lambda x:x["pos"]))]:
        for step in [1,2,4,8,-1,-2,-4,-8]:
            used=set()
            for idx,w in enumerate(ws):
                if idx in used: continue
                run=[w]; used.add(idx); cur=w["off"]
                while True:
                    found=None; found_i=None
                    for j,u in enumerate(ws):
                        if j in used: continue
                        if u["off"]==cur+step:
                            found=u; found_i=j; break
                    if found is None: break
                    run.append(found); used.add(found_i); cur=found["off"]
                if len(run)>=6:
                    arrays.append({"type":"x86_stack_opcode_immediates","ordering":ordering,"step":step,"start_off":run[0]["off"],"values":[x["value"] for x in run],"positions":[x["pos"] for x in run[:40]]})
    # Also group consecutive program writes even when offsets are not perfect.
    bypos=sorted(writes,key=lambda x:x["pos"])
    cur=[]
    last=None
    for w in bypos:
        if last is None or w["pos"]-last<=16:
            cur.append(w)
        else:
            if len(cur)>=6:
                arrays.append({"type":"x86_program_order_immediates","ordering":"program_near","step":0,"start_off":cur[0]["off"],"values":[x["value"] for x in cur],"positions":[x["pos"] for x in cur[:40]]})
            cur=[w]
        last=w["pos"]
    if len(cur)>=6:
        arrays.append({"type":"x86_program_order_immediates","ordering":"program_near","step":0,"start_off":cur[0]["off"],"values":[x["value"] for x in cur],"positions":[x["pos"] for x in cur[:40]]})
    out=[]; seen=set()
    for a in arrays:
        vals=tuple(a["values"])
        if vals not in seen and 6<=len(vals)<=512:
            seen.add(vals); out.append(a)
    return out[:80]
def rf_reverse_immediate_agent_fast(report, root, data):
    """No objdump dependency; direct x86 opcode immediate deobfuscation."""
    arrays=rf_extract_x86_stack_immediates_from_bytes(data)
    candidates=[]
    for a in arrays:
        for d in rf_deobfuscate_byte_sequence(a["values"],a["type"])[:25]:
            candidates.append({**d,"array_type":a["type"],"array_meta":{k:v for k,v in a.items() if k!="values"},"input_hex":bytes(a["values"][:256]).hex()})
    if not candidates:
        return []
    out=[]; seen=set()
    for c in sorted(candidates,key=lambda x:x.get("score",0),reverse=True):
        k=(c.get("method"),c.get("key"),c.get("text","")[:160])
        if k not in seen:
            seen.add(k); out.append(c)
        if len(out)>=80: break
    art=rf_art(root,report,"reverse_x86_immediate_fast_candidates.json",json.dumps(out,indent=2,ensure_ascii=False),"reverseforge_x86_immediate_fast",310,"Fast direct x86 stack immediate deobfuscation without objdump.")
    for c in out[:25]:
        txt=c.get("text","").strip()
        flags=[ux_canonical_flag(f) for f in c.get("flags",[]) if smartsolve_strict_target_flag_ok(f)]
        for f in rf_canonical_from_decoded_text(txt):
            if f not in flags:
                flags.append(f)
        for f in flags:
            if f not in report.setdefault("flags",[]): report["flags"].append(f)
            try: msf_trace(report,"ReverseImmediateFast flag",f"{c.get('array_type')} -> {c.get('method')} {c.get('key')} -> {txt!r} -> {f}",340,art.get("path") if art else "",f)
            except Exception: pass
            report.setdefault("answer_candidates",[]).append({"value":f,"source":"ReverseImmediateFast","why":f"Decoded from x86 stack immediate array using {c.get('method')} key={c.get('key')}.","score":390})
    sf_trace(report,"ReverseImmediateFast",f"{len(arrays)} direct x86 arrays; {len(out)} candidates",300,art.get("path") if art else "")
    return [art] if art else []
def rf_fast_binary_analyze_file(pid, path, root, i, total):
    p=Path(path)
    data=p.read_bytes()
    rel=str(p.relative_to(root)) if str(p).startswith(str(root)) else p.name
    report={
        "id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":rel,"kind":"binary",
        "size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest(),"magic":data[:32].hex(),
        "flags":[],"weak_flag_candidates":[],"verified_flags":[],"verified_flags_visible":[],"strings":[],"outputs":[],"previews":[],
        "commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"transformations":[],"findings":[],
        "next_steps":[],"solve_trace":[],"agent_trace":[],"answer_candidates":[],"flag_wrapping_helpers":[],"evidence_scored_candidates":[]
    }
    try: report["strings"]=py_strings(data,limit=2200)
    except Exception: report["strings"]=[]
    # Exact strings flags.
    for f in vf_primary_flags("\n".join(report["strings"]),limit=30,scan_limit=80000):
        if f not in report["flags"]: report["flags"].append(f)
    # Fast direct immediate scan first.
    try: rf_reverse_immediate_agent_fast(report,root,data)
    except Exception as e:
        try: msf_trace(report,"ReverseImmediateFast failed",str(e),0)
        except Exception: pass
    # If fast direct scan found nothing useful, fall back to objdump agent.
    if not report.get("flags") and not any("reverseforge" in str(a.get("kind","")).lower() for a in report.get("artifacts",[])):
        try: rf_reverse_immediate_agent(report,root,data,data[:150000].decode("utf-8","ignore"))
        except Exception as e:
            try: msf_trace(report,"ReverseImmediateAgent failed",str(e),0)
            except Exception: pass
    # Minimal metadata after solve, not before.
    for tool,cmd,timeout in [("file",["file",str(p)],3),("readelf_header",["readelf","-h",str(p)],4)]:
        try:
            if exists(cmd[0]):
                r=run(cmd,timeout)
                report["outputs"].append({"tool":tool,"ok":r.get("ok"),"cmd":r.get("cmd"),"out":r.get("out","")[:30000]})
        except Exception: pass
    # Numeric only if explicit.
    hint=(ux_statement_text(report)+" "+p.name+" "+" ".join(report.get("strings",[])[:80])).lower()
    if any(k in hint for k in ["numeric","drebėj","drebej","coefficient","coeff","double","float","table","lentel"]):
        try: wf_scan_numeric_tables(data,root,report)
        except Exception: pass
    promoted=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        if wf_flag_has_solve_evidence(report,f):
            promoted.append(f)
    promoted=sorted(list(dict.fromkeys(promoted)), key=lambda f: rf_flag_priority_score(f) if "rf_flag_priority_score" in globals() else 0, reverse=True)
    # For binary reverse, show only the best promoted flag unless there is exact strings evidence for several.
    report["flags"]=promoted[:1]
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: report["flag_wrapping_helpers"]=[]
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    if report["flags"]:
        report["findings"].append({"score":540,"type":"reverseforge_flag","value":report["flags"][0],"why":"Fast x86 immediate solver recovered high-confidence evidence-backed ctf_cs flag."})
    else:
        report["next_steps"].append({"priority":95,"step":"Open Reverse/SprintForge artifacts.","why":"Binary was processed with immediate deobfuscation."})
    return report
def sf_binary_needs_numeric(report, path):
    p=Path(path)
    hint=(ux_statement_text(report)+" "+p.name).lower()
    return any(k in hint for k in ["numeric","numerical","drebėj","drebej","coefficient","coeff","double","float","table","lentel","analizator"])
def rf_fast_binary_analyze_file(pid, path, root, i, total):
    p=Path(path)
    data=p.read_bytes()
    rel=str(p.relative_to(root)) if str(p).startswith(str(root)) else p.name
    report={
        "id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":rel,"kind":"binary",
        "size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest(),"magic":data[:32].hex(),
        "flags":[],"weak_flag_candidates":[],"verified_flags":[],"verified_flags_visible":[],"strings":[],"outputs":[],"previews":[],
        "commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"transformations":[],"findings":[],
        "next_steps":[],"solve_trace":[],"agent_trace":[],"answer_candidates":[],"flag_wrapping_helpers":[],"evidence_scored_candidates":[]
    }
    try: report["strings"]=py_strings(data,limit=1800)
    except Exception: report["strings"]=[]
    for f in vf_primary_flags("\n".join(report["strings"]),limit=30,scan_limit=80000):
        if f not in report["flags"]: report["flags"].append(f)
    # Fast no-objdump immediate scanner.
    try: rf_reverse_immediate_agent_fast(report,root,data)
    except Exception as e:
        try: msf_trace(report,"ReverseImmediateFast failed",str(e),0)
        except Exception: pass
    # Fallback objdump only if fast scanner found no reverse artifacts and no flags.
    if not report.get("flags") and not any("reverseforge" in str(a.get("kind","")).lower() for a in report.get("artifacts",[])):
        try: rf_reverse_immediate_agent(report,root,data,data[:150000].decode("utf-8","ignore"))
        except Exception as e:
            try: msf_trace(report,"ReverseImmediateAgent failed",str(e),0)
            except Exception: pass
    # Numeric table ONLY for explicit task name/statement hints, never generic ELF strings.
    if sf_binary_needs_numeric(report,p):
        try: wf_scan_numeric_tables(data,root,report)
        except Exception: pass
    # Minimal metadata after solving.
    for tool,cmd,timeout in [("file",["file",str(p)],3)]:
        try:
            if exists(cmd[0]):
                r=run(cmd,timeout)
                report["outputs"].append({"tool":tool,"ok":r.get("ok"),"cmd":r.get("cmd"),"out":r.get("out","")[:12000]})
        except Exception: pass
    promoted=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        if wf_flag_has_solve_evidence(report,f):
            promoted.append(f)
    promoted=sorted(list(dict.fromkeys(promoted)), key=lambda f: rf_flag_priority_score(f) if "rf_flag_priority_score" in globals() else 0, reverse=True)
    report["flags"]=promoted[:1]
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: report["flag_wrapping_helpers"]=[]
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    if report["flags"]:
        report["findings"].append({"score":540,"type":"reverseforge_flag","value":report["flags"][0],"why":"Fast x86 immediate solver recovered high-confidence evidence-backed ctf_cs flag."})
    else:
        report["next_steps"].append({"priority":95,"step":"Open Reverse/SprintForge artifacts.","why":"Binary was processed with immediate deobfuscation."})
    return report
def sf_is_compact_answer_text(s):
    s=str(s or "").strip()
    if not (6<=len(s)<=180): return False
    if "\n" in s: s=s.strip()
    if re.fullmatch(r"[A-Za-z0-9_\-:.+]+", s):
        # strong if leet/hash-ish plus meaningful word boundary
        low=s.lower()
        if any(w in low for w in ["cyber","sprint","flag","secret","raktas","slapta","calc","you","vilnius","cwe"]):
            return True
        if "_" in s and re.search(r"[a-z]{3,}", low):
            return True
    return False
def sf_handle_decoded_blob(report, root, blob, label, source_art=None, score=220):
    arts=[]
    blob=bytes(blob or b"")
    txt=blob[:300000].decode("utf-8","ignore")
    if txt.strip():
        art=sf_art(root,report,f"{safe(label)}_decoded_text.txt",txt,"sprintforge_decoded_text",score,"Decoded/decompressed text blob.")
        if art: arts.append(art)
        sf_promote_from_text(report,txt,"SprintForge EmbeddedCompression",f"{label} decoded text",art.get("path") if art else source_art,score+30)
        # If it is a single compact answer line, add/promote wrapper.
        line=txt.strip()
        if sf_is_compact_answer_text(line):
            sf_add_body_candidate(report,line,"SprintForge EmbeddedCompression",f"{label} produced compact answer text",score+55,promote=True,artifact=art.get("path") if art else source_art)
    # Recursive embedded extraction on decompressed blob.
    try: af_parse_embedded_files(report,root,blob,label)
    except Exception: pass
    try: af_decompress_recursive(report,root,blob,label,0,2)
    except Exception: pass
    return arts
def sf_embedded_compression_agent(report, root, data):
    """Search common archive/compression signatures anywhere in the bytes, not only after image end marker."""
    import bz2 as _bz2, gzip as _gzip, lzma as _lzma, zlib as _zlib, io as _io, zipfile as _zipfile
    data=bytes(data or b"")
    arts=[]
    if len(data)<8:
        return []
    sigs=[]
    for sig,name in [(b"PK\x03\x04","zip"),(b"BZh","bzip2"),(b"\x1f\x8b\x08","gzip"),(b"\xfd7zXZ\x00","xz"),(b"\x28\xb5\x2f\xfd","zstd")]:
        for m in re.finditer(re.escape(sig), data):
            # Skip true file header for the container itself only if whole file is that type? Still process once.
            sigs.append((m.start(),name))
    # also PNG text chunk special: any trailing non-png compressed payload.
    seen=set()
    for off,name in sorted(sigs,key=lambda x:x[0])[:80]:
        key=(off,name)
        if key in seen: continue
        seen.add(key)
        chunk=data[off:]
        # Avoid treating the outer PNG/JPEG itself as zip false; no PK in normal PNG.
        try:
            if name=="zip":
                bio=_io.BytesIO(chunk)
                if _zipfile.is_zipfile(bio):
                    bio.seek(0)
                    outdir=root/"generated"/"sprintforge"/safe(report.get("name","file"))/f"embedded_zip_{off}"
                    outdir.mkdir(parents=True,exist_ok=True)
                    with _zipfile.ZipFile(bio) as z:
                        names=z.namelist()
                        manifest={"offset":off,"names":names}
                        for n in names[:80]:
                            try:
                                raw=z.read(n)
                                out=(outdir/safe(n))
                                out.parent.mkdir(parents=True,exist_ok=True)
                                out.write_bytes(raw)
                                child_art={"kind":"sprintforge_embedded_zip_file","name":out.name,"path":str(out),"url":"/api/raw?path="+str(out),"source":"SprintForge","score":230,"note":f"Extracted from embedded ZIP at offset {off}: {n}","exists":True,"size":out.stat().st_size,"file":report.get("rel","")}
                                report.setdefault("artifacts",[]).append(child_art); report.setdefault("transformations",[]).append(child_art); arts.append(child_art)
                                sf_handle_decoded_blob(report,root,raw,f"embedded_zip_{off}_{n}",child_art.get("path"),230)
                            except Exception as e:
                                manifest.setdefault("errors",[]).append([n,str(e)])
                        mart=sf_art(root,report,f"embedded_zip_{off}_manifest.json",json.dumps(manifest,indent=2,ensure_ascii=False),"sprintforge_embedded_zip",240,f"Embedded ZIP carved at byte offset {off}.")
                        if mart: arts.append(mart)
            elif name=="bzip2":
                try:
                    dec=_bz2.decompress(chunk)
                    art=sf_art(root,report,f"embedded_bzip2_{off}.bin",dec,"sprintforge_embedded_bzip2",260,f"BZip2 stream decompressed from byte offset {off}.")
                    if art: arts.append(art)
                    arts += sf_handle_decoded_blob(report,root,dec,f"embedded_bzip2_{off}",art.get("path") if art else "",270)
                except Exception:
                    pass
            elif name=="gzip":
                try:
                    dec=_gzip.decompress(chunk)
                    art=sf_art(root,report,f"embedded_gzip_{off}.bin",dec,"sprintforge_embedded_gzip",230,f"Gzip stream decompressed from byte offset {off}.")
                    if art: arts.append(art)
                    arts += sf_handle_decoded_blob(report,root,dec,f"embedded_gzip_{off}",art.get("path") if art else "",240)
                except Exception:
                    pass
            elif name=="xz":
                try:
                    dec=_lzma.decompress(chunk)
                    art=sf_art(root,report,f"embedded_xz_{off}.bin",dec,"sprintforge_embedded_xz",230,f"XZ/LZMA stream decompressed from byte offset {off}.")
                    if art: arts.append(art)
                    arts += sf_handle_decoded_blob(report,root,dec,f"embedded_xz_{off}",art.get("path") if art else "",240)
                except Exception:
                    pass
            elif name=="zstd":
                try:
                    import zstandard as _zstd
                    dec=_zstd.ZstdDecompressor().decompress(chunk, max_output_size=80_000_000)
                    art=sf_art(root,report,f"embedded_zstd_{off}.bin",dec,"sprintforge_embedded_zstd",230,f"Zstd stream decompressed from byte offset {off}.")
                    if art: arts.append(art)
                    arts += sf_handle_decoded_blob(report,root,dec,f"embedded_zstd_{off}",art.get("path") if art else "",240)
                except Exception:
                    pass
        except Exception as e:
            sf_trace(report,"EmbeddedCompression error",f"{name}@{off}: {e}",0)
    if arts:
        sf_trace(report,"EmbeddedCompressionAgent",f"{len(arts)} embedded compression/archive artifacts",260,arts[0].get("path"))
    return arts
def sf_tail_embedded_agent(report, root, data):
    """Extract and process data after common image/file end markers plus compression signatures."""
    data=bytes(data or b"")
    arts=[]
    markers=[(b"IEND\xaeB`\x82","png_iend"),(b"\xff\xd9","jpeg_eoi")]
    for marker,name in markers:
        idx=data.find(marker)
        if idx>=0:
            end=idx+len(marker)
            tail=data[end:]
            if len(tail)>=8:
                art=sf_art(root,report,f"{name}_tail.bin",tail,"sprintforge_tail_data",170,f"Data appended after {name} marker.")
                if art: arts.append(art)
                arts += sf_embedded_compression_agent(report,root,tail)
                txt=tail[:200000].decode("utf-8","ignore")
                if txt.strip():
                    sf_promote_from_text(report,txt,"SprintForge TailData","text in appended tail",art.get("path") if art else "",190)
    # Important: also scan whole file for embedded compression even if PNG end marker not found.
    arts += sf_embedded_compression_agent(report,root,data)
    return arts
def sf_audio_image_combo_agent(report, root, data):
    """Safe image/audio auto route. Avoid heavy full LSB brute-force unless explicitly hinted."""
    p=Path(report.get("path",""))
    arts=[]
    if p.suffix.lower()==".wav":
        try: arts += msf_audio_agent(report,root,p,data,data[:200000].decode("utf-8","ignore"))
        except Exception: pass
        return arts
    if report.get("kind")=="image" or p.suffix.lower() in [".png",".jpg",".jpeg",".bmp",".gif",".webp"]:
        # 1) embedded archive/compression first: solves Herbas-style tasks.
        try: arts += sf_tail_embedded_agent(report,root,data)
        except Exception as e: sf_trace(report,"Tail/embedded image failed",str(e),0)
        # 2) QR repair if hinted/small.
        try:
            if "qr" in ux_statement_text(report).lower() or len(data)<700000:
                arts += msf_qr_checkerboard_agent(report,root,p)
        except Exception: pass
        # 3) Expensive Piet/tile/LSB only when statement hints stego/memories/colors, but skip generic forensics images.
        hint=(ux_statement_text(report)+" "+p.name).lower()
        if any(k in hint for k in ["piet","atsimin","memories","spalv","colors","lsb","stego","žinut","zinut"]) and len(data)<3_500_000:
            try:
                # Avoid full wf_writeup_agents because it includes slow Python LSB. Run selective fast-ish agents.
                wf_extract_piet_from_grid(p,root,report)
                wf_tile_puzzle_artifacts(p,root,report)
                # LSB only if specifically hinted and image is not too large.
                if any(k in hint for k in ["lsb","stego","žinut","zinut"]) and len(data)<900000:
                    wf_zsteg_like_lsb_extract(p,root,report)
            except Exception as e:
                sf_trace(report,"SelectiveImageAgents failed",str(e),0)
    return arts
_prev_sf_route_file_agents_embedded = sf_route_file_agents
def sf_route_file_agents(report, root, data):
    # First universal embedded scan. This catches PNG+BZip2, JPG+ZIP, etc.
    try:
        sf_embedded_compression_agent(report,root,data)
    except Exception as e:
        sf_trace(report,"Universal embedded compression failed",str(e),0)
    # Then normal route; safe image agent override above prevents heavy LSB by default.
    return _prev_sf_route_file_agents_embedded(report,root,data)
def sf_embedded_compression_agent(report, root, data):
    import bz2 as _bz2, gzip as _gzip, lzma as _lzma, io as _io, zipfile as _zipfile
    data=bytes(data or b"")
    arts=[]
    if len(data)<8: return []
    existing={(a.get("kind"),a.get("name"),a.get("size")) for a in report.get("artifacts",[])}
    sigs=[]
    for sig,name in [(b"PK\x03\x04","zip"),(b"BZh","bzip2"),(b"\x1f\x8b\x08","gzip"),(b"\xfd7zXZ\x00","xz"),(b"\x28\xb5\x2f\xfd","zstd")]:
        for m in re.finditer(re.escape(sig), data):
            sigs.append((m.start(),name))
    seen=set()
    for off,name in sorted(sigs,key=lambda x:x[0])[:50]:
        if (off,name) in seen: continue
        seen.add((off,name))
        chunk=data[off:]
        try:
            if name=="zip":
                bio=_io.BytesIO(chunk)
                if _zipfile.is_zipfile(bio):
                    bio.seek(0)
                    outdir=root/"generated"/"sprintforge"/safe(report.get("name","file"))/f"embedded_zip_{off}"
                    outdir.mkdir(parents=True,exist_ok=True)
                    with _zipfile.ZipFile(bio) as z:
                        names=z.namelist()
                        manifest={"offset":off,"names":names}
                        for n in names[:80]:
                            try:
                                raw=z.read(n)
                                out=outdir/safe(n)
                                out.parent.mkdir(parents=True,exist_ok=True)
                                out.write_bytes(raw)
                                child_art={"kind":"sprintforge_embedded_zip_file","name":out.name,"path":str(out),"url":"/api/raw?path="+str(out),"source":"SprintForge","score":230,"note":f"Extracted from embedded ZIP at offset {off}: {n}","exists":True,"size":out.stat().st_size,"file":report.get("rel","")}
                                k=(child_art["kind"],child_art["name"],child_art["size"])
                                if k not in existing:
                                    existing.add(k); report.setdefault("artifacts",[]).append(child_art); report.setdefault("transformations",[]).append(child_art); arts.append(child_art)
                                sf_handle_decoded_blob(report,root,raw,f"embedded_zip_{off}_{n}",child_art.get("path"),230)
                            except Exception as e:
                                manifest.setdefault("errors",[]).append([n,str(e)])
                        mart=sf_art(root,report,f"embedded_zip_{off}_manifest.json",json.dumps(manifest,indent=2,ensure_ascii=False),"sprintforge_embedded_zip",240,f"Embedded ZIP carved at byte offset {off}.")
                        if mart: arts.append(mart)
            elif name=="bzip2":
                try:
                    dec=_bz2.decompress(chunk)
                    # Avoid duplicate same decoded text.
                    dec_hash=hashlib.sha256(dec).hexdigest()[:16]
                    if any(dec_hash in str(a.get("note","")) for a in report.get("artifacts",[])):
                        continue
                    art=sf_art(root,report,f"embedded_bzip2_{off}.bin",dec,"sprintforge_embedded_bzip2",260,f"BZip2 stream decompressed from byte offset {off}; sha16={dec_hash}.")
                    if art: arts.append(art)
                    arts += sf_handle_decoded_blob(report,root,dec,f"embedded_bzip2_{off}",art.get("path") if art else "",270)
                except Exception: pass
            elif name=="gzip":
                try:
                    dec=_gzip.decompress(chunk)
                    dec_hash=hashlib.sha256(dec).hexdigest()[:16]
                    if any(dec_hash in str(a.get("note","")) for a in report.get("artifacts",[])): continue
                    art=sf_art(root,report,f"embedded_gzip_{off}.bin",dec,"sprintforge_embedded_gzip",230,f"Gzip stream decompressed from byte offset {off}; sha16={dec_hash}.")
                    if art: arts.append(art)
                    arts += sf_handle_decoded_blob(report,root,dec,f"embedded_gzip_{off}",art.get("path") if art else "",240)
                except Exception: pass
            elif name=="xz":
                try:
                    dec=_lzma.decompress(chunk)
                    dec_hash=hashlib.sha256(dec).hexdigest()[:16]
                    if any(dec_hash in str(a.get("note","")) for a in report.get("artifacts",[])): continue
                    art=sf_art(root,report,f"embedded_xz_{off}.bin",dec,"sprintforge_embedded_xz",230,f"XZ/LZMA stream decompressed from byte offset {off}; sha16={dec_hash}.")
                    if art: arts.append(art)
                    arts += sf_handle_decoded_blob(report,root,dec,f"embedded_xz_{off}",art.get("path") if art else "",240)
                except Exception: pass
            elif name=="zstd":
                try:
                    import zstandard as _zstd
                    dec=_zstd.ZstdDecompressor().decompress(chunk, max_output_size=80_000_000)
                    dec_hash=hashlib.sha256(dec).hexdigest()[:16]
                    if any(dec_hash in str(a.get("note","")) for a in report.get("artifacts",[])): continue
                    art=sf_art(root,report,f"embedded_zstd_{off}.bin",dec,"sprintforge_embedded_zstd",230,f"Zstd stream decompressed from byte offset {off}; sha16={dec_hash}.")
                    if art: arts.append(art)
                    arts += sf_handle_decoded_blob(report,root,dec,f"embedded_zstd_{off}",art.get("path") if art else "",240)
                except Exception: pass
        except Exception as e:
            sf_trace(report,"EmbeddedCompression error",f"{name}@{off}: {e}",0)
    if arts:
        sf_trace(report,"EmbeddedCompressionAgent",f"{len(arts)} embedded compression/archive artifacts",260,arts[0].get("path"))
    return arts
