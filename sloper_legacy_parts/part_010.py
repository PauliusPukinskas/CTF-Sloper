# Auto-split from sloper_legacy_monolith.py lines 8740-...
def msf_fwht_inverse(vals):
    vals=list(vals)
    n=1
    while n<len(vals): n*=2
    if n!=len(vals): return None
    a=[int(x) for x in vals]
    h=1
    while h<n:
        for i in range(0,n,h*2):
            for j in range(i,i+h):
                x=a[j]; y=a[j+h]
                a[j]=(x+y)//2
                a[j+h]=(x-y)//2
        h*=2
    return bytes((x&255) for x in a)
def msf_transform_agent(report, root, data, text):
    """Detect numeric transform outputs: Walsh-Hadamard/inverse bytes."""
    arts=[]
    nums=[]
    for tok in re.findall(r"[-+]?\d+", text[:200000]):
        try:
            nums.append(int(tok))
        except Exception:
            pass
        if len(nums)>8192: break
    if len(nums)>=8:
        # Try chunks at power-of-two lengths.
        for n in [8,16,32,64,128,256,512,1024,2048,4096]:
            if len(nums)>=n:
                raw=msf_fwht_inverse(nums[:n])
                if raw:
                    s=raw.decode("utf-8","ignore")
                    if wf_ascii_quality(s)>=100 or vf_primary_flags(s) or msf_alt_flags(s):
                        art=msf_art(root,report,f"fwht_inverse_{n}.txt",s,"multistepforge_fwht_inverse",175,"Inverse Walsh-Hadamard candidate output.")
                        if art: arts.append(art)
                        af_run_text_decoders(report,root,s,"FWHTInverse",600)
                        break
    if arts:
        msf_trace(report,"TransformAgent",f"{len(arts)} FWHT/numeric transform artifacts",170,arts[0].get("path"))
    return arts
def msf_web_static_agent(report, root, path, data, text):
    """Static web source audit: routes, dangerous functions, traversal/upload clues."""
    p=Path(path)
    suffix=p.suffix.lower()
    if suffix not in [".php",".js",".ts",".py",".rb",".go",".java",".conf",".html",".htaccess"] and p.name.lower() not in ["dockerfile","docker-compose.yml","routes.php","web.php"]:
        return []
    clues=[]
    patterns=[
        ("path_traversal", r"\.\.|path\.join|send_file|readfile|file_get_contents|open\(|download|avatar|filename|user_id"),
        ("upload", r"\$_FILES|multer|upload|move_uploaded_file|storage_path|public_path"),
        ("command_injection", r"shell_exec|system\(|exec\(|passthru|subprocess|os\.system|popen|convert|imagemagick"),
        ("sql_injection", r"raw\(|query\(|select .* from|\$_GET|\$_POST"),
        ("jwt_cookie_session", r"jwt|cookie|session|secret_key|APP_KEY|serialize|unserialize"),
        ("apache_dir_listing", r"Options\s+\+?Indexes|DirectoryIndex|Alias|DocumentRoot"),
        ("http3_quic", r"http3|quic|udp|443"),
    ]
    for name,pat in patterns:
        if re.search(pat,text,re.I):
            clues.append(name)
    if clues:
        snippet="\n".join(line for line in text.splitlines()[:2000] if any(re.search(p,text,re.I) for _,p in []))[:1]
        obj={"file":report.get("rel",""),"clues":sorted(set(clues)),"note":"Static web audit only; live web exploitation is not run."}
        art=msf_art(root,report,"web_static_audit_clues.json",json.dumps(obj,indent=2),"multistepforge_web_static_audit",145,"Static source clues for web challenge.")
        msf_trace(report,"WebStaticAgent",", ".join(sorted(set(clues))),145,art.get("path") if art else "")
        return [art] if art else []
    return []
def msf_archive_zstd_sb3_agent(report, root, path, data):
    p=Path(path)
    arts=[]
    if p.suffix.lower() in [".zstd",".zst",".zstd"] or data[:4] == b"\x28\xb5\x2f\xfd":
        try:
            import zstandard as zstd
            raw=zstd.ZstdDecompressor().decompress(data, max_output_size=50_000_000)
            art=msf_art(root,report,"zstd_decompressed.bin",raw,"multistepforge_zstd_decompressed",155,"Zstandard decompressed data.")
            if art:
                arts.append(art)
                txt=raw.decode("utf-8","ignore")
                if txt: af_run_text_decoders(report,root,txt,"ZstdDecompressed",700)
        except Exception as e:
            msf_trace(report,"ZstdAgent failed",str(e),0)
    # Scratch .sb3 is zip; pyd/pkg zip extraction already exists, but add specific trace.
    if p.suffix.lower()==".sb3":
        try:
            af_parse_embedded_files(report,root,data,"scratch_sb3")
            msf_trace(report,"ScratchAgent","SB3 is zip-like; extracted project assets where possible.",130)
        except Exception:
            pass
    return arts
def msf_run_training_agents(report, root, data):
    p=Path(report.get("path",""))
    text=data.decode("utf-8","ignore")
    msf_trace(report,"start",f"kind={report.get('kind')} file={p.name}",60)
    msf_learn_repo_context(report,root,data,text)
    try: msf_timestamp_agent(report,root)
    except Exception as e: msf_trace(report,"TimestampAgent failed",str(e),0)
    try: msf_audio_agent(report,root,p,data,text)
    except Exception as e: msf_trace(report,"AudioAgent failed",str(e),0)
    try: msf_transform_agent(report,root,data,text)
    except Exception as e: msf_trace(report,"TransformAgent failed",str(e),0)
    try: msf_web_static_agent(report,root,p,data,text)
    except Exception as e: msf_trace(report,"WebStaticAgent failed",str(e),0)
    try: msf_archive_zstd_sb3_agent(report,root,p,data)
    except Exception as e: msf_trace(report,"ArchiveAgent failed",str(e),0)
    if report.get("kind")=="image" or p.suffix.lower() in [".png",".jpg",".jpeg",".bmp",".gif",".webp"]:
        try: msf_qr_checkerboard_agent(report,root,p)
        except Exception as e: msf_trace(report,"QRRepairAgent failed",str(e),0)
    # Refresh candidates
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: pass
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    return report
_prev_af_aggressive_v37 = af_aggressive_autosolve_report
def af_aggressive_autosolve_report(report, root, data):
    report=_prev_af_aggressive_v37(report,root,data)
    if not report.get("_multistepforge_done"):
        try:
            msf_run_training_agents(report,root,data)
            report["_multistepforge_done"]=True
        except Exception as e:
            msf_trace(report,"MultiStepForge failed",str(e),0)
    return report
_prev_vf_postprocess_v37 = vf_postprocess
def vf_postprocess(report, root):
    report=_prev_vf_postprocess_v37(report,root)
    data=b""
    try: data=Path(report.get("path","")).read_bytes()[:10_000_000]
    except Exception: pass
    if not report.get("_multistepforge_done"):
        try:
            msf_run_training_agents(report,root,data)
            report["_multistepforge_done"]=True
        except Exception as e:
            msf_trace(report,"MultiStepForge failed",str(e),0)
    # keep weak/promoted logic from v36 by re-evaluating candidates only, not random promotion
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    return report
_prev_project_summary_v37 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v37(reports,meta)
    # Add alternate flags bucket from answer candidates.
    alts=[]
    for a in summary.get("answer_candidates",[]):
        val=a.get("value","")
        if ALT_FLAG_RE.fullmatch(val or ""):
            alts.append(a)
    summary["alternate_flag_candidates"]=alts[:120]
    # Raise MultiStepForge artifacts
    arts=summary.get("artifacts",[])
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "multistepforge" in txt: s+=650
        if any(k in txt for k in ["timestamp","qr","audio","stft","fwht","web_static","zstd"]): s+=250
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(arts,key=pri,reverse=True)[:1600]
    # Add guidance if alts exist
    if alts:
        summary.setdefault("workflow_steps",[]).insert(0,{"priority":99,"step":"Review Alternate Flag Candidates.","why":"Training ZIP uses non-primary formats like gigem{...}; actual target may still require ctf_cs{...}."})
    return summary
def msf_project_once(root, name):
    marker=root/"generated"/"multistepforge"/"_once"
    marker.mkdir(parents=True, exist_ok=True)
    p=marker/(safe(name)+".done")
    if p.exists():
        return False
    try:
        p.write_text(now() if "now" in globals() else "done", encoding="utf-8")
    except Exception:
        pass
    return True
def msf_run_training_agents(report, root, data):
    p=Path(report.get("path",""))
    text=data.decode("utf-8","ignore")
    msf_trace(report,"start",f"kind={report.get('kind')} file={p.name}",60)
    msf_learn_repo_context(report,root,data,text)
    # Project-level timestamp scan only once, otherwise projects with many tiny files become slow.
    try:
        if msf_project_once(root,"timestamp_agent"):
            msf_timestamp_agent(report,root)
    except Exception as e:
        msf_trace(report,"TimestampAgent failed",str(e),0)
    # File-level agents are routed by file type / hints.
    try:
        if p.suffix.lower() in [".wav",".txt",".csv",".dat"] and (p.suffix.lower()==".wav" or "stft" in text.lower() or "complex" in text.lower()):
            msf_audio_agent(report,root,p,data,text)
    except Exception as e:
        msf_trace(report,"AudioAgent failed",str(e),0)
    try:
        if p.suffix.lower() in [".txt",".csv",".dat",".out",".dump"] and len(data)<2_000_000:
            msf_transform_agent(report,root,data,text)
    except Exception as e:
        msf_trace(report,"TransformAgent failed",str(e),0)
    try:
        msf_web_static_agent(report,root,p,data,text)
    except Exception as e:
        msf_trace(report,"WebStaticAgent failed",str(e),0)
    try:
        msf_archive_zstd_sb3_agent(report,root,p,data)
    except Exception as e:
        msf_trace(report,"ArchiveAgent failed",str(e),0)
    if (report.get("kind")=="image" or p.suffix.lower() in [".png",".jpg",".jpeg",".bmp",".gif",".webp"]):
        # QR repair only if the challenge hints at QR/timing/checkerboard OR image is small enough.
        hint=(ff_statement_text(report) if "ff_statement_text" in globals() else "").lower()+" "+p.name.lower()
        if any(k in hint for k in ["qr","quick","response","checker","timing"]) or len(data)<600_000:
            try: msf_qr_checkerboard_agent(report,root,p)
            except Exception as e: msf_trace(report,"QRRepairAgent failed",str(e),0)
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: pass
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    return report
STRICT_PRIMARY_FLAG_RE = re.compile(r"\bctf_cs\{[A-Za-z0-9][A-Za-z0-9_\-:.+]{5,140}\}", re.I)
def ux_canonical_flag(flag):
    flag=str(flag or "").strip()
    m=re.match(r"(?i)^ctf_cs\{(.+)\}$", flag)
    if not m:
        return flag
    return "ctf_cs{" + m.group(1).strip() + "}"
def ux_statement_text(report):
    try:
        root=Path(report.get("path","")).parents[1]
        meta=jread(root/"project.json",{})
        return ((meta.get("title","") or "")+"\n"+(meta.get("statement","") or "")+"\n"+(meta.get("category","") or ""))
    except Exception:
        return ""
def ux_statement_allows_raw_answer(report_or_text):
    txt = report_or_text if isinstance(report_or_text, str) else ux_statement_text(report_or_text)
    low=str(txt or "").lower()
    raw_phrases=[
        "be flago formato","be formato","be wrapper","be prefix","be prefikso",
        "atsakymas be","pateikti tik atsakyma","pateik tik atsakyma","submit the answer only",
        "without flag format","without wrapper","no wrapper","raw answer","answer only",
        "flag format is not required","nereikia formato","nereikia ctf_cs"
    ]
    return any(p in low for p in raw_phrases)
def smartsolve_strict_target_flag_ok(flag, meta=None):
    flag=str(flag or "").strip()
    if not STRICT_PRIMARY_FLAG_RE.fullmatch(flag):
        return False
    inner=flag_inner(flag)
    low=inner.lower().strip()
    norm=low.replace(".", "_").replace("-", "_")
    if low in PLACEHOLDER_INNERS:
        return False
    if any(x in norm for x in ["placeholder","your_flag","not_the_flag","notflag","insert_flag","change_me","sample_flag","dummy_flag"]):
        return False
    # block task-format placeholders
    if any(w in norm for w in ["pavadinimas","gatves","gatvės","pastato","numeris","vietos","rastos","frazė","fraze","tekstas","sha256_kodas","rastastekstas","rastas_tekstas","rasta_fraze","rasta_frazė"]):
        return False
    if len(inner)<8 or len(inner)>140:
        return False
    if any(ord(c)<32 or ord(c)>126 for c in inner):
        return False
    if "ctf_cs" in low:
        return False
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_\-:.+]{7,140}", inner):
        return False
    # Heuristic against random false positives: short all-alpha/all-random-looking strings are weak.
    if len(inner)<12 and not re.search(r"[_\-.:\d]", inner):
        return False
    if len(inner)<=10 and re.fullmatch(r"[A-Za-z0-9]{8,10}", inner) and not re.search(r"\d", inner):
        return False
    return True
def vf_primary_flags(text, limit=80, scan_limit=60000):
    text=str(text or "")[:scan_limit]
    hits=[]; seen=set()
    for m in STRICT_PRIMARY_FLAG_RE.finditer(text):
        cand=ux_canonical_flag(m.group(0))
        if smartsolve_strict_target_flag_ok(cand):
            k=cand.lower()
            if k not in seen:
                seen.add(k); hits.append(cand)
                if len(hits)>=limit: break
    return hits
def vf_answer_score(text, source=""):
    s=str(text or "").strip()
    if not s or len(s)<3 or len(s)>180:
        return 0
    low=s.lower()
    score=0
    if STRICT_PRIMARY_FLAG_RE.search(s):
        m=STRICT_PRIMARY_FLAG_RE.search(s).group(0)
        if smartsolve_strict_target_flag_ok(m): score+=320
    if re.fullmatch(r"[a-fA-F0-9]{64}",s): score+=155
    if re.fullmatch(r"[a-fA-F0-9]{32,40}",s): score+=105
    if re.fullmatch(r"-?\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+",s): score+=125
    if re.fullmatch(r"[A-Za-z0-9_\-:.+/@]{5,140}",s): score+=40
    if any(k in low for k in ["answer","atsakymas","ats:","raktas","key","secret","slapta","slaptažodis","pass:","password","code","kodas","token"]): score+=70
    # Alternate CTF formats are training noise for this event; do not boost them.
    if re.fullmatch(r"[a-z0-9_]{2,16}\{[^}]{4,160}\}", s, re.I) and not s.lower().startswith("ctf_cs{"):
        score-=120
    if len(s)>100 and not re.search(r"[A-Za-z0-9_\-:.+/@]{20,}",s): score-=80
    if any(w in low for w in ["vėliavėlės formatas","veliaveles formatas","formatas ctf_cs","užduotis","jūsų užduotis","jusu uzduotis","kur ... yra"]): score-=140
    if any(w in low for w in ["sample","dummy","fake","placeholder","example","ctf_cs{...}"]): score-=130
    if "�" in s: score-=80
    if source and any(x in source.lower() for x in ["ocr","qr","artifact","chain","solve","numeric","lsb","timestamp"]): score+=20
    return score
def vf_add_answer(cands, value, source, why="", score_bonus=0):
    value=str(value or "").strip()
    if not value:
        return
    m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|slaptazodis|password|pass|code|kodas|token)\s*[:=]\s*(.+)$",value,re.I)
    if m and len(m.group(1).strip())<160:
        value=m.group(1).strip()
    if STRICT_PRIMARY_FLAG_RE.fullmatch(value):
        value=ux_canonical_flag(value)
    # Ignore training-event alternate flags unless they appear as explicit raw answer line.
    if re.fullmatch(r"[a-z0-9_]{2,16}\{[^}]{4,160}\}", value, re.I) and not value.lower().startswith("ctf_cs{"):
        if "raw" not in str(source).lower() and "answer" not in str(source).lower():
            return
    sc=vf_answer_score(value, source)+int(score_bonus)
    if sc>=70:
        cands.append({"value":value[:220],"source":str(source)[:180],"why":str(why)[:320],"score":sc})
def vf_collect_answer_candidates(report):
    cands=[]
    raw_mode=ux_statement_allows_raw_answer(report)
    for f in report.get("flags",[])[:120]:
        f=ux_canonical_flag(f)
        if smartsolve_strict_target_flag_ok(f):
            vf_add_answer(cands,f,"promoted flag","strict ctf_cs candidate",270)
    joined=ux_statement_text(report)+"\n"+"\n".join(report.get("strings",[])[:1600])+"\n"+"\n".join((o.get("out") or "")[:7000] for o in report.get("outputs",[])[:120])
    joined+="\n"+"\n".join((c.get("output") or "")[:7000] for c in report.get("chain_results",[])[:140])
    # strict ctf_cs from any decoded source
    for f in vf_primary_flags(joined,limit=80,scan_limit=120000):
        vf_add_answer(cands,f,"strict_ctf_cs_scan","ctf_cs found in combined decoded evidence",260)
    markers=["answer","atsakymas","ats","raktas","key","secret","slapta","slaptažodis","slaptazodis","password","pass","code","kodas","token","login","vartotojas","user","username"]
    for line in joined.splitlines()[:4500]:
        line=line.strip(); low=line.lower()
        if not (3<=len(line)<=260): continue
        if any(k in low for k in markers):
            m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|slaptazodis|password|pass|code|kodas|token|login|vartotojas|user|username)\s*[:=]\s*(.+)$",line,re.I)
            if m:
                val=m.group(1).strip()
                src="raw_answer_marker" if raw_mode else "answer_marker"
                why="Statement appears to allow raw answer." if raw_mode else "Value after answer/key marker."
                vf_add_answer(cands,val,src,why,120 if raw_mode else 90)
            else:
                vf_add_answer(cands,line,"answer_context","answer-like line",45)
    # Artifact scan
    for a in report.get("artifacts",[])[:260]:
        p=Path(a.get("path",""))
        try:
            if not p.exists() or not p.is_file() or p.stat().st_size>=900000: continue
            if not (p.suffix.lower() in [".txt",".json",".log",".md",".csv",".xml",".svg"] or any(x in p.name.lower() for x in ["ocr","decoded","answer","secret","key","brief","strings","constants","chain","decompressed","timestamp","qr","numeric","lsb","piet"])):
                continue
            txt=p.read_text(encoding="utf-8",errors="ignore")[:20000]
            for f in vf_primary_flags(txt,limit=10,scan_limit=25000):
                vf_add_answer(cands,f,"artifact:"+a.get("kind",""),"strict ctf_cs in artifact text",int(a.get("score",0)//3)+120)
            for line in txt.splitlines()[:160]:
                line=line.strip()
                low=line.lower()
                if 3<=len(line)<=220 and any(k in low for k in markers):
                    m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|slaptazodis|password|pass|code|kodas|token)\s*[:=]\s*(.+)$",line,re.I)
                    if m:
                        vf_add_answer(cands,m.group(1).strip(),"artifact_raw_answer" if raw_mode else "artifact_value:"+a.get("kind",""),"value after marker in artifact",int(a.get("score",0)//5)+95)
        except Exception:
            pass
    out=[]; seen=set()
    for x in sorted(cands,key=lambda z:z.get("score",0),reverse=True):
        val=x.get("value","").strip()
        if STRICT_PRIMARY_FLAG_RE.fullmatch(val):
            val=ux_canonical_flag(val); x["value"]=val
        k=val.lower()
        if k and k not in seen:
            seen.add(k); out.append(x)
    return out[:260]
def ff_candidate_to_flag_helpers(report):
    # Only suggest ctf_cs wrapping when statement does NOT say raw answer.
    if ux_statement_allows_raw_answer(report):
        return []
    helpers=[]
    for a in report.get("answer_candidates",[])[:80]:
        val=str(a.get("value","")).strip()
        if not val or val.lower().startswith("ctf_cs{"):
            continue
        if re.fullmatch(r"[a-z0-9_]{2,16}\{[^}]{4,160}\}", val, re.I):
            continue
        m=re.search(r"[:=]\s*([A-Za-z0-9_\-:.+/@]{3,160})\s*$",val)
        clean=m.group(1) if m else val
        body=re.sub(r"\s+","_",clean.strip())
        body=re.sub(r"[^A-Za-z0-9_\-:.+]","",body)
        if 4<=len(body)<=120:
            sugg=f"ctf_cs{{{body}}}"
            helpers.append({"answer":val,"suggested_flag":sugg,"source":a.get("source",""),"score":a.get("score",0)-5,"why":"Candidate is not a flag by itself; try wrapper only if the task requires ctf_cs{...}."})
    out=[]; seen=set()
    for h in sorted(helpers,key=lambda x:x.get("score",0),reverse=True):
        k=h["suggested_flag"].lower()
        if k not in seen:
            seen.add(k); out.append(h)
    return out[:70]
_prev_project_summary_v38 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v38(reports, meta)
    # Remove training-format alternate flags from the main UI.
    summary["alternate_flag_candidates"]=[]
    # Normalize flags and remove weak/random ones.
    flags=[]
    seen=set()
    for x in summary.get("flags",[]):
        f=ux_canonical_flag(x.get("flag",""))
        if smartsolve_strict_target_flag_ok(f) and f.lower() not in seen:
            y=dict(x); y["flag"]=f; y["status"]="ctf_cs_only_promoted"
            flags.append(y); seen.add(f.lower())
    summary["flags"]=flags
    summary["exact_flags"]=flags
    # Raw answers are separate, only when statement says raw/no wrapper.
    raw=[]
    if ux_statement_allows_raw_answer((meta.get("title","") or "")+"\n"+(meta.get("statement","") or "")):
        for a in summary.get("answer_candidates",[])[:80]:
            val=a.get("value","")
            if val and not val.lower().startswith("ctf_cs{"):
                raw.append(a)
        summary["flag_wrapping_helpers"]=[]
    summary["raw_answer_candidates"]=raw[:80]
    # Remove workflow mention of Alternate Flags.
    summary["workflow_steps"]=[w for w in summary.get("workflow_steps",[]) if "alternate" not in str(w).lower()]
    if raw:
        summary.setdefault("workflow_steps",[]).insert(0,{"priority":99,"step":"Review Raw Answer Candidates.","why":"Statement appears to allow answers without ctf_cs wrapper."})
    return summary
def wf_flag_has_solve_evidence(report, flag):
    flag=ux_canonical_flag(flag)
    if not smartsolve_strict_target_flag_ok(flag):
        return False
    low=flag.lower()
    support=0
    sources=[]
    # Exact flag in original strings/text is valid evidence if it passes strict filters.
    for s in report.get("strings",[])[:1500]:
        if low in str(s).lower():
            support+=2; sources.append("strings")
            break
    for o in report.get("outputs",[])[:120]:
        if low in str(o.get("out","")).lower():
            support+=2; sources.append("tool_output:"+str(o.get("tool","")))
            break
    for c in report.get("chain_results",[])[:220]:
        if low in str(c.get("output","")).lower() or flag in [ux_canonical_flag(x) for x in (c.get("flags") or [])]:
            support+=2; sources.append("chain:"+str(c.get("type","")))
    for a in report.get("artifacts",[])[:300]:
        p=Path(a.get("path",""))
        try:
            if p.exists() and p.is_file() and p.stat().st_size<700000:
                txt=p.read_text(encoding="utf-8",errors="ignore")
                if low in txt.lower():
                    support+=2; sources.append("artifact:"+str(a.get("kind","")))
        except Exception:
            pass
    for t in report.get("solve_trace",[])+report.get("agent_trace",[]):
        if low in str(t).lower():
            support+=1; sources.append("trace")
    report.setdefault("flag_evidence",{})[flag]={"support":support,"sources":sources[:12]}
    return support>=2
_prev_vf_postprocess_v38_fix = vf_postprocess
def vf_postprocess(report, root):
    report=_prev_vf_postprocess_v38_fix(report, root)
    # Re-promote strict direct ctf_cs flags from original strings/outputs/artifacts if v36 evidence filter made them weak.
    candidates=[]
    combined="\n".join(report.get("strings",[])[:1500])+"\n"+"\n".join((o.get("out") or "")[:8000] for o in report.get("outputs",[])[:120])
    candidates += vf_primary_flags(combined,limit=80,scan_limit=120000)
    for c in report.get("chain_results",[])[:180]:
        candidates += [ux_canonical_flag(f) for f in c.get("flags",[]) if smartsolve_strict_target_flag_ok(f)]
    for f in candidates:
        f=ux_canonical_flag(f)
        if wf_flag_has_solve_evidence(report,f) and f not in report.setdefault("flags",[]):
            report["flags"].append(f)
    # Remove promoted flags from weak list.
    promoted=set(x.lower() for x in report.get("flags",[]))
    report["weak_flag_candidates"]=[x for x in report.get("weak_flag_candidates",[]) if str(x.get("flag","")).lower() not in promoted]
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: pass
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    return report
def vf_collect_answer_candidates(report):
    cands=[]
    raw_mode=ux_statement_allows_raw_answer(report)
    for f in report.get("flags",[])[:120]:
        f=ux_canonical_flag(f)
        if smartsolve_strict_target_flag_ok(f):
            vf_add_answer(cands,f,"promoted flag","strict ctf_cs candidate",270)
    joined=ux_statement_text(report)+"\n"+"\n".join(report.get("strings",[])[:1400])+"\n"+"\n".join((o.get("out") or "")[:5000] for o in report.get("outputs",[])[:80])
    joined+="\n"+"\n".join((c.get("output") or "")[:5000] for c in report.get("chain_results",[])[:100])
    for f in vf_primary_flags(joined,limit=80,scan_limit=90000):
        vf_add_answer(cands,f,"strict_ctf_cs_scan","ctf_cs found in combined decoded evidence",260)
    markers=["answer","atsakymas","ats","raktas","key","secret","slapta","slaptažodis","slaptazodis","password","pass","code","kodas","token","login","vartotojas","user","username"]
    for line in joined.splitlines()[:3000]:
        line=line.strip(); low=line.lower()
        if not (3<=len(line)<=260): continue
        if any(k in low for k in markers):
            m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|slaptazodis|password|pass|code|kodas|token|login|vartotojas|user|username)\s*[:=]\s*(.+)$",line,re.I)
            if m:
                val=m.group(1).strip()
                src="raw_answer_marker" if raw_mode else "answer_marker"
                why="Statement appears to allow raw answer." if raw_mode else "Value after answer/key marker."
                vf_add_answer(cands,val,src,why,120 if raw_mode else 90)
            else:
                vf_add_answer(cands,line,"answer_context","answer-like line",45)
    # Bounded fast artifact scan: never read full file.
    for a in report.get("artifacts",[])[:120]:
        p=Path(a.get("path",""))
        try:
            if not p.exists() or not p.is_file() or p.stat().st_size>=1_200_000: continue
            name=p.name.lower()
            if not (p.suffix.lower() in [".txt",".json",".log",".md",".csv",".xml",".svg"] or any(x in name for x in ["ocr","decoded","answer","secret","key","brief","strings","constants","chain","decompressed","timestamp","qr","numeric","lsb","piet"])):
                continue
            txt=p.read_bytes()[:22000].decode("utf-8","ignore")
            for f in vf_primary_flags(txt,limit=10,scan_limit=24000):
                vf_add_answer(cands,f,"artifact:"+a.get("kind",""),"strict ctf_cs in artifact text",int(a.get("score",0)//3)+120)
            for line in txt.splitlines()[:120]:
                line=line.strip(); low=line.lower()
                if 3<=len(line)<=220 and any(k in low for k in markers):
                    m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|slaptazodis|password|pass|code|kodas|token)\s*[:=]\s*(.+)$",line,re.I)
                    if m:
                        vf_add_answer(cands,m.group(1).strip(),"artifact_raw_answer" if raw_mode else "artifact_value:"+a.get("kind",""),"value after marker in artifact",int(a.get("score",0)//5)+95)
        except Exception:
            pass
    out=[]; seen=set()
    for x in sorted(cands,key=lambda z:z.get("score",0),reverse=True):
        val=x.get("value","").strip()
        if STRICT_PRIMARY_FLAG_RE.fullmatch(val):
            val=ux_canonical_flag(val); x["value"]=val
        k=val.lower()
        if k and k not in seen:
            seen.add(k); out.append(x)
    return out[:240]
def ux_route_hints(report, data):
    p=Path(report.get("path",""))
    text=data[:250000].decode("utf-8","ignore")
    statement=ux_statement_text(report).lower()
    route=(report.get("kind","")+" "+p.suffix.lower()+" "+p.name.lower()+" "+statement+" "+text[:5000].lower())
    return p,text,route
def vf_postprocess(report, root):
    # Final v38 routed pipeline: avoids running every heavy agent for every file.
    data=b""
    try: data=Path(report.get("path","")).read_bytes()[:10_000_000]
    except Exception: pass
    p,text,route=ux_route_hints(report,data)
    kind=report.get("kind","generic")
    # Direct strict flags from initial strings/text.
    for f in vf_primary_flags(text+"\n"+"\n".join(report.get("strings",[])[:1000]),limit=60,scan_limit=100000):
        if f not in report.setdefault("flags",[]): report["flags"].append(f)
    try:
        af_text_osint_agent(report,root,data,text)
    except Exception as e:
        try: af_trace(report,"TextOSINTAgent skipped/failed",str(e),0)
        except Exception: pass
    # Crypto only if clues or high encoded content.
    if any(x in route for x in ["crypto","cipher","xor","rsa","jwt","hash","base64","base32","hex","šif","sif","decode","encoded"]) or re.search(r"[A-Za-z0-9+/=_-]{40,}|[A-Fa-f0-9]{48,}", text):
        try: af_crypto_agent(report,root,data,text)
        except Exception as e: 
            try: af_trace(report,"CryptoAgent failed",str(e),0)
            except Exception: pass
    # Image/stego.
    if kind=="image" or p.suffix.lower() in [".png",".jpg",".jpeg",".bmp",".gif",".webp"]:
        try:
            arts, previews = vf_visual_lab(p, root, report)
            existing=set(a.get("path") for a in report.get("artifacts",[]))
            for a in arts:
                if a.get("path") not in existing:
                    report.setdefault("artifacts",[]).append(a); existing.add(a.get("path"))
            report.setdefault("previews",[]).extend(previews)
        except Exception: pass
        try: wf_writeup_agents(report,root,data)
        except Exception as e: msf_trace(report,"Writeup image agents failed",str(e),0)
        if any(x in route for x in ["qr","quick","response","checker","timing"]) or len(data)<700000:
            try: msf_qr_checkerboard_agent(report,root,p)
            except Exception: pass
    # Binary/rev/numeric.
    if kind in ["binary","python_bytecode"] or p.suffix.lower() in [".exe",".dll",".elf",".so",".bin",".dat",".pyc"]:
        try: af_rev_agent(report,root,data,text)
        except Exception: pass
        try: wf_scan_numeric_tables(data,root,report)
        except Exception as e: msf_trace(report,"NumericTableAgent failed",str(e),0)
    # PCAP.
    if kind=="pcap" or p.suffix.lower() in [".pcap",".pcapng"]:
        try: af_pcap_agent(report,root,data,text)
        except Exception: pass
    # Archive/compression.
    if kind=="archive" or p.suffix.lower() in [".zip",".gz",".tgz",".tar",".7z",".rar",".xz",".bz2",".zst",".zstd",".sb3"] or data[:4] in [b"PK\x03\x04", b"\x28\xb5\x2f\xfd"]:
        try: af_forensics_agent(report,root,data,text)
        except Exception: pass
        try: msf_archive_zstd_sb3_agent(report,root,p,data)
        except Exception: pass
    # Timestamp once per project.
    try:
        if msf_project_once(root,"timestamp_agent"):
            msf_timestamp_agent(report,root)
    except Exception:
        pass
    # Audio/STFT/transform.
    try:
        if p.suffix.lower()==".wav" or "stft" in route or "complex64" in route:
            msf_audio_agent(report,root,p,data,text)
    except Exception: pass
    try:
        if p.suffix.lower() in [".txt",".csv",".dat",".out",".dump"] and len(data)<2_000_000 and any(x in route for x in ["hadamard","walsh","fwht","numbers","stft"]):
            msf_transform_agent(report,root,data,text)
    except Exception: pass
    # Static web audit only source-like files.
    try: msf_web_static_agent(report,root,p,data,text)
    except Exception: pass
    # Child artifact shallow pass after routed agents.
    try: ff_child_artifact_autopass(root, report, max_children=35)
    except Exception: pass
    # Evidence and final candidates.
    promoted=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        if wf_flag_has_solve_evidence(report,f):
            promoted.append(f)
    report["flags"]=promoted
    report["weak_flag_candidates"]=[]
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: report["flag_wrapping_helpers"]=[]
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    return report
def ux_is_path_noise(value):
    s=str(value or "").strip()
    low=s.lower()
    if low.startswith(("/mnt/","/home/","c:\\","/tmp/")):
        return True
    if re.search(r"/projects/|/generated/|/files/|\\projects\\|\\generated\\|\\files\\", low):
        return True
    if len(s)>80 and re.search(r"[\\/]", s) and "." in Path(s).name:
        return True
    return False
_prev_vf_add_answer_v38_path = vf_add_answer
def vf_add_answer(cands, value, source, why="", score_bonus=0):
    value=str(value or "").strip()
    if not value or ux_is_path_noise(value):
        return
    _prev_vf_add_answer_v38_path(cands,value,source,why,score_bonus)
_prev_vf_collect_answer_candidates_v38_path = vf_collect_answer_candidates
def vf_collect_answer_candidates(report):
    out=_prev_vf_collect_answer_candidates_v38_path(report)
    clean=[]; seen=set()
    for x in out:
        v=x.get("value","")
        if ux_is_path_noise(v):
            continue
        k=v.lower()
        if k not in seen:
            seen.add(k); clean.append(x)
    return clean[:240]
def rf_art(root, report, name, content, kind="reverseforge_artifact", score=100, note=""):
    outdir=root/"generated"/"reverseforge"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"ReverseForge","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        try: msf_trace(report,"ReverseForge artifact",f"{kind}: {p.name}",score,str(p))
        except Exception: pass
        return art
    except Exception as e:
        try: msf_trace(report,"ReverseForge artifact failed",f"{name}: {e}",0)
        except Exception: pass
        return None
def rf_printable_score(bs):
    if not bs:
        return 0
    printable=sum(1 for b in bs if 32<=b<127 or b in [9,10,13])
    ratio=printable/max(1,len(bs))
    txt=bytes(bs).decode("utf-8","ignore")
    low=txt.lower()
    score=int(ratio*100)
    if re.search(r"\{[a-z0-9_+\-:.]{4,120}\}", low): score+=180
    if "ctf_cs{" in low: score+=260
    if re.search(r"[a-z0-9]{3,}_[a-z0-9_]{3,}", low): score+=80
    if any(k in low for k in ["flag","key","secret","calc","you","pass","token"]): score+=35
    if len(bs)>=8: score+=25
    if len(bs)>160: score-=30
    return score
def rf_rotl8(x,r):
    return ((x<<r)|(x>>(8-r))) & 255
def rf_rotr8(x,r):
    return ((x>>r)|(x<<(8-r))) & 255
def rf_canonical_from_decoded_text(txt):
    txt=str(txt or "").strip()
    hits=[]
    for f in vf_primary_flags(txt,limit=20,scan_limit=5000):
        hits.append(f)
    # If decoded text is {body}, produce ctf_cs{body}
    for m in re.finditer(r"\{([A-Za-z0-9_\-:.+]{4,120})\}", txt):
        body=m.group(1)
        cand=f"ctf_cs{{{body}}}"
        if smartsolve_strict_target_flag_ok(cand):
            hits.append(cand)
    # If decoded text itself is flag-body-like, offer wrapper.
    clean=txt.strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_\-:.+]{7,120}", clean) and ("_" in clean or any(c.isdigit() for c in clean)):
        cand=f"ctf_cs{{{clean}}}"
        if smartsolve_strict_target_flag_ok(cand):
            hits.append(cand)
    out=[]; seen=set()
    for h in hits:
        h=ux_canonical_flag(h)
        if h.lower() not in seen:
            seen.add(h.lower()); out.append(h)
    return out
def rf_deobfuscate_byte_sequence(seq, source="sequence"):
    """Try common CTF transforms on a byte array and return ranked candidates."""
    seq=bytes(int(x)&255 for x in seq)
    out=[]
    def add(method,key,bs):
        txt=bytes(bs).decode("utf-8","ignore")
        sc=rf_printable_score(bs)
        flags=rf_canonical_from_decoded_text(txt)
        if flags: sc+=220
        if sc>=160:
            out.append({"method":method,"key":key,"text":txt,"hex":bytes(bs).hex(),"score":sc,"flags":flags,"source":source})
    # raw
    add("raw",None,seq)
    # xor/add/sub
    for k in range(256):
        add("xor",k,bytes(b^k for b in seq))
        add("add",k,bytes((b+k)&255 for b in seq))
        add("sub",k,bytes((b-k)&255 for b in seq))
    # not, xor-not
    add("not",None,bytes((~b)&255 for b in seq))
    for r in range(1,8):
        add("rol",r,bytes(rf_rotl8(b,r) for b in seq))
        add("ror",r,bytes(rf_rotr8(b,r) for b in seq))
    # de-duplicate
    best=[]; seen=set()
    for c in sorted(out,key=lambda x:x.get("score",0),reverse=True):
        key=(c["method"],c.get("key"),c["text"][:160])
        if key not in seen:
            seen.add(key); best.append(c)
        if len(best)>=80: break
    return best
def rf_extract_stack_immediate_arrays(disasm):
    """Parse objdump Intel syntax stack immediate writes into contiguous arrays."""
    lines=str(disasm or "").splitlines()
    writes=[]
    # Examples:
    # c7 45 c0 29 00 00 00  mov DWORD PTR [rbp-0x40],0x29
    # c6 45 f0 41           mov BYTE PTR [rbp-0x10],0x41
    # mov    DWORD PTR [rbp-0x40],0x29
    pat=re.compile(r"mov\s+(?:(?:BYTE|WORD|DWORD|QWORD)\s+PTR\s+)?\[(r[bs]p)([+-]0x[0-9a-f]+|[+-]\d+)?\],\s*(0x[0-9a-f]+|\d+)", re.I)
    for line in lines:
        m=pat.search(line)
        if not m:
            continue
        base=m.group(1).lower()
        off_s=m.group(2) or "+0"
        val_s=m.group(3)
        try:
            off=int(off_s.replace("+",""),0)
            val=int(val_s,0)
        except Exception:
            continue
        # Only likely char/byte-ish arrays stored as DWORD/BYTE.
        if 0<=val<=0xff:
            writes.append({"base":base,"off":off,"value":val,"line":line.strip()})
    if len(writes)<4:
        return []
    arrays=[]
    for base in sorted(set(w["base"] for w in writes)):
        ws=sorted([w for w in writes if w["base"]==base], key=lambda x:x["off"])
        # Group runs with step 1,2,4,8 in stack offset order.
        for step in [1,2,4,8,-1,-2,-4,-8]:
            used=set()
            for i,w in enumerate(ws):
                if i in used: continue
                run=[w]; used.add(i)
                cur=w["off"]
                # forward
                while True:
                    nxt=None; nxt_i=None
                    for j,u in enumerate(ws):
                        if j in used: continue
                        if u["off"]==cur+step:
                            nxt=u; nxt_i=j; break
                    if nxt is None: break
                    run.append(nxt); used.add(nxt_i); cur=nxt["off"]
                if len(run)>=6:
                    seq=[x["value"] for x in run]
                    arrays.append({"type":"stack_immediates","base":base,"step":step,"start_off":run[0]["off"],"values":seq,"lines":[x["line"] for x in run[:40]]})
    # Deduplicate by values
    out=[]; seen=set()
    for a in arrays:
        k=tuple(a["values"])
        if k not in seen and 6<=len(k)<=512:
            seen.add(k); out.append(a)
    return out[:80]
def rf_extract_rodata_hex_sequences(objdump_text):
    """Collect byte sequences from objdump -s sections."""
    seqs=[]
    for line in str(objdump_text or "").splitlines():
        # objdump -s lines:  4020 2931333e 310d2b3d ...
        m=re.match(r"\s*[0-9a-fA-F]{4,16}\s+((?:[0-9a-fA-F]{2,8}\s+){1,8})", line)
        if not m: continue
        hexpart=re.sub(r"\s+","",m.group(1))
        if len(hexpart)>=12 and len(hexpart)%2==0:
            try:
                bs=bytes.fromhex(hexpart)
                if len(bs)>=6:
                    seqs.append(list(bs))
            except Exception:
                pass
    # merge neighboring short rows later? Return rows and sliding windows from raw concat.
    concat=[]
    for s in seqs:
        concat+=s
    out=[]
    if len(concat)>=6:
        out.append({"type":"objdump_section_hex_concat","values":concat[:2000]})
        # split by zero runs
        cur=[]
        for b in concat:
            if b==0:
                if len(cur)>=6: out.append({"type":"objdump_section_hex_zero_split","values":cur})
                cur=[]
            else:
                cur.append(b)
        if len(cur)>=6: out.append({"type":"objdump_section_hex_zero_split","values":cur})
    return out[:80]
