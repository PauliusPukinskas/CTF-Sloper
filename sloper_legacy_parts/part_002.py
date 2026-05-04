# Auto-split from sloper_legacy_monolith.py lines 1773-...
def verifyloop_promote_artifacts(root,report):
    if report.get("flags"):
        report["promoted_children"]=[]; return []
    source_path=str(report.get("path",""))
    if "_verifyloop_children" in source_path:
        report["promoted_children"]=[]; return []
    child_dir=root/"files"/"_verifyloop_children"; child_dir.mkdir(parents=True,exist_ok=True)
    promoted=[]; allowed={"decoded","decompress","xor","pcap_exported_object","pcap_tcp_stream","pcap_dns","pdf_text","pdf_attachment","pdf_image","archive_child","binary_unpacked","rsa_params","jwt_candidates","hash_candidates"}
    for item in (report.get("transformations",[])+report.get("intermediate_files",[]))[:100]:
        try:
            src=Path(item.get("path",""))
            if not src.exists() or not src.is_file() or src.stat().st_size<=0 or src.stat().st_size>4_000_000: continue
            kind=item.get("kind",""); score=int(item.get("score",0) or 0); name_low=src.name.lower(); contains=False
            try:
                if src.stat().st_size<=500_000:
                    sample=src.read_text(encoding="utf-8",errors="ignore")[:20000]
                    contains=bool(fast_flag_matches(sample,limit=1) or "ctf_cs" in sample.lower())
            except Exception: contains=False
            useful=kind in allowed or (score>=110 and contains) or any(x in name_low for x in ["decoded","stream","dns","rsa","jwt","xor","decompress","unpacked"])
            noisy=any(x in name_low for x in ["contact_sheet","preview","summary","strings_ascii","strings_utf16"]) and not contains
            if not useful or noisy: continue
            h=hashlib.sha256(src.read_bytes()[:2_000_000]).hexdigest()[:16]
            dest=child_dir/(h+"_"+safe(src.name))
            if not dest.exists(): shutil.copy2(src,dest); promoted.append({"source":str(src),"path":str(dest),"kind":kind,"score":score})
            if len(promoted)>=10: break
        except Exception: pass
    report["promoted_children"]=promoted[:10]
    return promoted[:10]
NOISE_EVIDENCE_TYPES = {"partial_ctf_cs", "brace_or_flag_fragment", "brace_fragment", "context_line"}
PROMOTED_STATUSES = {"confirmed", "likely"}
def is_noisy_candidate_text(value, why="", typ=""):
    value = str(value or "")
    low = (value + "\n" + str(why) + "\n" + str(typ)).lower()
    if not value.strip():
        return True
    if any(x in low for x in ["ctf_cs{...}", "sample_flag", "dummy", "fake", "placeholder", "example flag", "format is", "flag format", "template"]):
        return True
    if typ in NOISE_EVIDENCE_TYPES and score_text(value) < 95:
        return True
    if len(value) > 2500 and "ctf_cs{" not in low:
        return True
    return False
def stableworkbench_artifacts_for_report(report):
    """Return a clean artifact browser list for one analyzed file."""
    items = []
    def add(kind, obj, source=""):
        if not isinstance(obj, dict):
            return
        path = obj.get("path") or obj.get("source") or ""
        name = obj.get("name") or (Path(path).name if path else kind)
        if not path:
            return
        p = Path(path)
        size = 0
        exists_flag = False
        try:
            exists_flag = p.exists()
            size = p.stat().st_size if exists_flag else 0
        except Exception:
            pass
        items.append({
            "kind": kind,
            "name": name,
            "path": path,
            "url": "/api/raw?path=" + path,
            "source": obj.get("source") or source or obj.get("note") or "",
            "score": int(obj.get("score", 0) or 0),
            "note": obj.get("note",""),
            "exists": exists_flag,
            "size": size,
            "file": report.get("rel","")
        })
    for x in report.get("transformations", [])[:500]:
        add("transformation:" + str(x.get("kind","artifact")), x, "Transform/derived artifact")
    for x in report.get("intermediate_files", [])[:500]:
        add("intermediate", x, "Intermediate generated artifact")
    for x in report.get("agent_files", [])[:200]:
        add("agent_note", x, "Agent note")
    for x in report.get("promoted_children", [])[:200]:
        add("promoted_child", x, "Promoted child artifact")
    for x in report.get("previews", [])[:240]:
        add("preview", x, "Image/media preview")
    # Extracted archive/binwalk folders may be dirs; still expose path for copy.
    for x in report.get("extracted", [])[:80]:
        if isinstance(x, str):
            items.append({
                "kind": "extracted_path",
                "name": Path(x).name,
                "path": x,
                "url": "/api/raw?path=" + x,
                "source": "extract_archive",
                "score": 40,
                "note": "Extraction output path",
                "exists": Path(x).exists(),
                "size": 0,
                "file": report.get("rel","")
            })
    # Deduplicate.
    out, seen = [], set()
    for it in sorted(items, key=lambda x: (x.get("exists", False), x.get("score", 0), x.get("size", 0)), reverse=True):
        k = (it.get("kind"), it.get("path"))
        if k not in seen:
            seen.add(k)
            out.append(it)
    return out[:700]
def stableworkbench_apply_report_postprocess(report, root=None):
    """Noise cleanup + artifact browser + safer promoted flags."""
    try:
        apply_verified_flags(report)
    except Exception:
        pass

    # Never let low/template candidates appear as primary flags.
    good = []
    for v in report.get("verified_flags", []):
        if v.get("status") in PROMOTED_STATUSES and not v.get("negative_reasons"):
            flag = v.get("flag","")
            if not is_noisy_candidate_text(flag, ";".join(v.get("negative_reasons", [])), "verified"):
                good.append(flag)
    report["flags"] = list(dict.fromkeys(good))[:30]

    # Clean findings. Keep verified candidates, strong chains, agent/tool plans, but suppress template noise.
    cleaned = []
    for f in report.get("findings", []):
        val = f.get("value","")
        typ = f.get("type","")
        why = f.get("why","")
        if is_noisy_candidate_text(val, why, typ):
            continue
        if str(typ).startswith("verified_flag_candidate:low"):
            continue
        cleaned.append(f)
    report["findings"] = sorted(cleaned, key=lambda x: x.get("score", 0), reverse=True)[:120]

    report["artifacts"] = stableworkbench_artifacts_for_report(report)
    return report
def project_summary(reports, meta):
    flags=[]; verified_all=[]; kinds={}; evidence=[]; chains=[]; actions=[]; missing=[]; agents=[]; transforms=[]; verifyloops=[]; artifacts=[]
    for r in reports:
        stableworkbench_apply_report_postprocess(r)
        kinds[r.get("kind","?")] = kinds.get(r.get("kind","?"),0)+1

        for v in r.get("verified_flags",[]):
            vv={"file":r.get("rel"),**v}; verified_all.append(vv)
            if v.get("status") in PROMOTED_STATUSES and not v.get("negative_reasons") and not is_noisy_candidate_text(v.get("flag",""), "", "verified"):
                flags.append({"file":r.get("rel"),"flag":v.get("flag"),"score":v.get("score",0),"status":v.get("status")})

        for f in r.get("findings",[])[:80]:
            val=f.get("value","")
            if not is_noisy_candidate_text(val, f.get("why",""), f.get("type","")):
                evidence.append({"file":r.get("rel"),**f})

        for c in r.get("chain_results",[])[:45]:
            out=(c.get("output","") or "")[:900]
            if c.get("score",0)>65 and not is_noisy_candidate_text(out, c.get("type",""), "chain"):
                chains.append({"file":r.get("rel"),"type":c.get("type"),"source":c.get("chain_source"),"score":c.get("score"),"output":out})

        for s in r.get("next_steps",[])[:10]:
            actions.append({"file":r.get("rel"),**s})
        for a in r.get("agent_runs",[])[:15]:
            agents.append({"file":r.get("rel"),"kind":r.get("kind"),**a})
        for t in r.get("transformations",[])[:50]:
            transforms.append({"file":r.get("rel"),**t})
        if r.get("verifyloop"):
            verifyloops.append({"file":r.get("rel"),"kind":r.get("kind"),**r.get("verifyloop",{})})
        for art in r.get("artifacts", [])[:160]:
            artifacts.append(art)
        for o in r.get("outputs",[]):
            if not o.get("ok") and "not installed" in (o.get("out","").lower()):
                missing.append((o.get("out","").split() or ["unknown"])[0])

    verified_all = sorted(verified_all,key=lambda x:x.get("score",0),reverse=True)[:180]
    evidence = sorted(evidence,key=lambda x:x.get("score",0),reverse=True)[:180]
    chains = sorted(chains,key=lambda x:x.get("score",0) or 0,reverse=True)[:120]
    artifacts = sorted(artifacts,key=lambda x:(x.get("exists",False),x.get("score",0),x.get("size",0)),reverse=True)[:500]
    exact=[f for f in flags if "ctf_cs{" in f.get("flag","").lower()]

    workflow=[]
    if exact:
        workflow.append({"priority":100,"step":"Submit/check top verified ctf_cs candidate.","why":"Candidate survived VerifyLoop noise filters and has supporting sources."})
    elif verified_all:
        workflow.append({"priority":92,"step":"Open Verified Flags; inspect possible candidates manually.","why":"Candidates exist, but none were promoted enough for automatic trust."})
    if evidence:
        workflow.append({"priority":90,"step":"Open Evidence Board top item.","why":"Highest scoring non-noisy evidence."})
    if artifacts:
        workflow.append({"priority":88,"step":"Open Artifacts and inspect generated derived files.","why":"All transformed/extracted outputs are collected there."})
    if chains:
        workflow.append({"priority":86,"step":"Open Chain Results for "+chains[0].get("file",""),"why":"Best derived output after noise filtering."})
    if not workflow:
        workflow.append({"priority":50,"step":"Open Files → priority file → Tools/Artifacts.","why":"No strong signal yet."})

    priority=sorted([{
        "file":r.get("rel"),
        "kind":r.get("kind"),
        "flags":len(r.get("flags",[])),
        "verified":len(r.get("verified_flags",[])),
        "artifacts":len(r.get("artifacts",[])),
        "findings":len(r.get("findings",[])),
        "chains":len(r.get("chain_results",[])),
        "top_score":max([x.get("score",0) for x in r.get("findings",[])]+[0])
    } for r in reports],key=lambda x:(x["flags"],x["verified"],x["top_score"],x["artifacts"]),reverse=True)[:120]

    return {
        "flags":flags[:80],
        "verified_flags":verified_all,
        "exact_flags":exact[:80],
        "kinds":kinds,
        "evidence_board":evidence,
        "top_findings":evidence,
        "top_chains":chains,
        "agents":sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:160],
        "transformations":sorted(transforms,key=lambda x:x.get("score",0),reverse=True)[:240],
        "artifacts":artifacts,
        "verifyloops":verifyloops[:160],
        "hypotheses":workflowbrain_project_hypotheses(reports) if "workflowbrain_project_hypotheses" in globals() else [],
        "workflow_steps":sorted(workflow+actions,key=lambda x:x.get("priority",0),reverse=True)[:160],
        "missing_tools":sorted(set(missing))[:100],
        "priority_files":priority
    }
def stableworkbench_limit_tool_output(result):
    """Keep manual tool cards readable and stop UI from choking."""
    if not isinstance(result, dict):
        return result
    out = result.get("out","")
    if isinstance(out, str) and len(out) > 90000:
        result["out"] = out[:90000] + "\n\n[StableWorkbench: output truncated for UI]"
    result["evidence"] = [e for e in result.get("evidence", []) if not is_noisy_candidate_text(e.get("value",""), e.get("why",""), e.get("type",""))][:80]
    result["decoders"] = result.get("decoders", [])[:80]
    return result
def internal_tool_result(path, toolname):
    p=Path(path)
    try:
        data=readbytes(p, 4_000_000)
    except Exception as e:
        return {"tool":toolname,"ok":False,"cmd":"internal:"+toolname,"out":"read failed: "+str(e),"missing":[],"install_hint":"","evidence":[],"decoders":[]}
    strings_list=py_strings(data, limit=3000)
    out=None
    if toolname=="magic_bytes":
        out="Magic/head bytes:\n"+data[:160].hex(" ")+"\n\nASCII preview:\n"+data[:800].decode("utf-8","replace")
    elif toolname=="strings":
        out="\n".join(strings_list)
    elif toolname=="strings_braces":
        lines=[s for s in strings_list if any(k in s.lower() for k in ["ctf_cs","flag","raktas","slapta"]) or "{" in s or "}" in s]
        out="\n".join(f"{i+1}:{line}" for i,line in enumerate(lines[:500]))
    elif toolname=="extract_ascii_context":
        lines=[]
        for i,s in enumerate(strings_list):
            low=s.lower()
            if any(k in low for k in ["ctf_cs","flag","raktas","slapta","key","secret","token","password"]) or "{" in s or "}" in s:
                ctx=strings_list[max(0,i-2):min(len(strings_list),i+3)]
                lines.append("\n".join(ctx))
        out="\n---\n".join(lines[:120])
    elif toolname=="grep_crypto_clues":
        pat=re.compile(r"rsa|aes|xor|base64|base32|base58|md5|sha1|sha256|jwt|nonce|iv|key|secret|n=|e=|c=|p=|q=", re.I)
        out="\n".join(s for s in strings_list if pat.search(s))[:50000]
    elif toolname=="grep_urls_tokens":
        matches=[]
        for s in strings_list:
            matches += re.findall(r"https?://[^\s'\"<>]+|eyJ[A-Za-z0-9_=.-]+|[A-Fa-f0-9]{32,64}", s)
            if len(matches)>500: break
        out="\n".join(matches[:500])
    elif toolname=="strings_utf16":
        try:
            txt=data.decode("utf-16le","ignore")
            out="\n".join(re.findall(r"[ -~]{4,}", txt)[:1200])
        except Exception:
            out=""
    elif toolname=="hashid_file":
        vals=[]
        for s in strings_list:
            for h in re.findall(r"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b", s):
                typ={32:"possible MD5/NTLM",40:"possible SHA1",64:"possible SHA256"}[len(h)]
                vals.append(f"{h} :: {typ}")
        out="\n".join(vals[:500])
    elif toolname=="sha256sum":
        out=hashlib.sha256(data).hexdigest()+"  "+str(p)
    elif toolname=="md5sum":
        out=hashlib.md5(data).hexdigest()+"  "+str(p)
    else:
        return None
    res={"tool":toolname,"ok":True,"cmd":"internal:"+toolname,"out":out[:120000],"missing":[],"install_hint":""}
    res["evidence"]=extract_flagish_text(res["out"])[:60]
    res["decoders"]=decode_candidates(res["out"], b"")[:50]
    return stableworkbench_limit_tool_output(res)
def run_tool_local(path,toolname,timeout=180):
    p=Path(path)
    if not p.exists():
        return {"tool":toolname,"ok":False,"cmd":"","out":"file not found","missing":[],"install_hint":""}
    internal=internal_tool_result(p,toolname)
    if internal is not None:
        return internal
    if toolname not in TOOL_COMMANDS:
        return {"tool":toolname,"ok":False,"cmd":"","out":"unknown tool","missing":[],"install_hint":""}
    try:
        cmd=TOOL_COMMANDS[toolname](p)
    except Exception as e:
        return {"tool":toolname,"ok":False,"cmd":"","out":"command build failed: "+str(e),"missing":[],"install_hint":""}
    miss=missing_deps(toolname,cmd)
    if miss:
        hint="Missing dependencies: "+", ".join(miss)+". Run bash FULL_INSTALL.sh."
        return {"tool":toolname,"ok":False,"cmd":" ".join(map(str,cmd)),"out":hint,"missing":miss,"install_hint":hint,"evidence":[],"decoders":[]}
    # Manual tool runs get the requested timeout, auto runs use smaller values in verifyloop_run_tools.
    res=run(cmd,timeout)
    res["tool"]=toolname; res["missing"]=[]; res["install_hint"]=""
    text=res.get("out","")
    res["evidence"]=extract_flagish_text(text)[:60]
    res["decoders"]=decode_candidates(text,b"")[:60]
    return stableworkbench_limit_tool_output(res)
def verifyloop_relevant_tools(path, kind):
    """Bounded auto tools. Full manual tools remain available in UI."""
    core=["file","magic_bytes","strings","strings_braces","extract_ascii_context","grep_crypto_clues","grep_urls_tokens"]
    by_kind={
        "text": core+["strings_utf16","hashid_file"],
        "generic": core+["strings_utf16","exiftool","binwalk","foremost","yara_basic"],
        "image": core+["exiftool","identify","pngcheck","png_chunks","zbarimg","tesseract","zsteg_all","steghide_info","stegseek","binwalk","binwalk_extract","foremost"],
        "pcap": core+["capinfos","tshark_protocols","tshark_http","tshark_dns","tshark_tcp0","tshark_tcp1","tshark_tcp2","tshark_files"],
        "pdf": core+["pdfinfo","pdftotext","pdfimages","pdfdetach_list","pdfdetach_extract","qpdf_check","exiftool","binwalk"],
        "archive": core+["seven_list","zipinfo","zip_comment","hashid_file","binwalk","binwalk_extract","foremost"],
        "binary": core+["readelf","elf_sections","elf_imports","checksec_basic","rabin2_info","rabin2_strings","r2_info","upx_test","objdump_rodata","nm"],
        "media": core+["ffprobe","soxi","spectrogram","exiftool","binwalk"],
        "sqlite": core+["sqlite_tables","sqlite_schema"],
        "apk": core+["apktool_decode","jadx_decompile"],
        "python_bytecode": core+["python_pyc_decompile","decompyle3"],
    }
    tools=by_kind.get(kind, by_kind["generic"])
    out=[]; seen=set()
    for t in tools:
        if t in TOOL_COMMANDS and t not in seen:
            seen.add(t); out.append(t)
    return out[:45]
def verifyloop_run_tools(pid, path, report, root):
    kind=report.get("kind","generic")
    tools=verifyloop_relevant_tools(path,kind)
    results=[]
    log(pid,f"StableWorkbench: {path.name} kind={kind} auto-tools={len(tools)}")
    slow={"binwalk_extract","foremost","tshark_files","pdfdetach_extract","pdfimages","apktool_decode","jadx_decompile","spectrogram","r2_info","zsteg_all","stegseek"}
    for tool in tools:
        try:
            timeout=35 if tool in slow else 5
            r=run_tool_local(path,tool,timeout)
            r["auto"]=True
            r["tool"]="stableworkbench:"+tool
            results.append(r)
            report.setdefault("commands",[]).append(r.get("cmd",""))
            for ev in r.get("evidence",[]) or []:
                val=ev.get("value","")
                if "ctf_cs{" in val.lower() and val not in report.setdefault("flags",[]):
                    report["flags"].append(val)
            for d in r.get("decoders",[]) or []:
                for f in d.get("flags",[]) or []:
                    if f not in report.setdefault("flags",[]):
                        report["flags"].append(f)
        except Exception as e:
            results.append({"tool":"stableworkbench:"+tool,"ok":False,"cmd":tool,"out":"StableWorkbench tool failed: "+str(e),"auto":True})
    added=verifyloop_add_outputs(report,results) if "verifyloop_add_outputs" in globals() else []
    return {"tools":tools,"added_outputs":len(added),"results":results}
def analyze_file(pid,path,root,i,total):
    progress(pid,min(94,int((i/max(1,total))*84)+6),f"Analyzing {path.name}")
    data=readbytes(path)
    fileout=run(["file",str(path)],8).get("out","") if exists("file") else ""
    kind=detect_kind(path,fileout)
    ss=py_strings(data)
    rep={"id":uuid.uuid4().hex[:10],"name":path.name,"path":str(path),"rel":str(path.relative_to(root)),"size":path.stat().st_size,"entropy":entropy(data[:2_000_000]),"kind":kind,"file":fileout,"fingerprint":{"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest()},"flags":list(dict.fromkeys(x.decode("utf-8","replace") for x in FLAG_BYTES_RE.findall(data))),"strings":ss[:900],"outputs":[],"previews":[],"commands":[],"extracted":[],"expert_contexts":[],"decoders":[],"chain_results":[],"intermediate_files":[],"findings":[],"next_steps":[],"hypotheses":[],"structured_clues":[],"agent_runs":[],"agent_files":[],"transformations":[],"verifyloop":{},"verified_flags":[],"promoted_children":[],"artifacts":[]}

    if kind=="archive":
        rep["extracted"]=extract_archive(path,root/"files")
    if kind=="image":
        pv,outs=image_lab(path,root)
        rep["previews"]+=pv
        rep["outputs"]+=outs
        for v in pv:
            for f in v.get("flags",[]):
                if f not in rep["flags"]:
                    rep["flags"].append(f)
    if kind=="media" and exists("ffmpeg"):
        spdir=root/"generated"/"media"/path.stem
        spdir.mkdir(parents=True,exist_ok=True)
        sp=spdir/"spectrogram.png"
        r=run(["ffmpeg","-y","-i",str(path),"-lavfi","showspectrumpic=s=1600x900",str(sp)],45)
        rep["outputs"].append({"tool":"spectrogram","ok":r["ok"],"cmd":r["cmd"],"out":r["out"]})
        if sp.exists():
            rep["previews"].append({"name":"spectrogram","url":"/api/raw?path="+str(sp),"path":str(sp),"score":15})

    # Fast initial core pass.
    for label,tpl,to in PIPE["common"]+PIPE.get(kind,[]):
        if label in ["objdump","readelf","r2 quick"] and kind!="binary":
            continue
        cmd=make_cmd(tpl,path)
        rep["commands"].append(" ".join(cmd))
        if cmd[0] not in ["bash","sh"] and not exists(cmd[0]):
            rep["outputs"].append({"tool":label,"ok":False,"cmd":" ".join(cmd),"out":cmd[0]+" not installed"})
            continue
        r=run(cmd,min(to,45))
        rep["outputs"].append({"tool":label,"ok":r["ok"],"cmd":r["cmd"],"out":r["out"]})
        for mf in fast_flag_matches(r.get("out",""), limit=20):
            if mf not in rep["flags"]:
                rep["flags"].append(mf)

    rep["verifyloop"]=verifyloop_run_tools(pid,path,rep,root)
    verifyloop_refresh_analysis(rep,data)
    rep["transformations"]=execute_transform_agents(rep,root,data)
    rep["intermediate_files"]=(rep.get("intermediate_files",[])+rep.get("transformations",[]))[:320]
    write_intermediate_files(rep,root)
    rep["agent_runs"],rep["agent_files"]=run_agent_forge(rep,root)
    rep["intermediate_files"]=(rep.get("intermediate_files",[])+rep.get("agent_files",[]))[:320]
    verifyloop_scan_transform_files(rep)
    verifyloop_refresh_analysis(rep,data)
    apply_verified_flags(rep)
    verifyloop_promote_artifacts(root,rep)
    rep["findings"]=rank_findings(rep)
    rep["next_steps"]=next_steps(rep)
    stableworkbench_apply_report_postprocess(rep,root)
    return rep
def analyze_project(pid):
    root=pdir(pid)
    meta=jread(meta_path(pid),{})
    progress(pid,1,"Preparing project")
    for p in list(all_files(root)):
        try:
            fo=run(["file",str(p)],8).get("out","") if exists("file") else ""
            if detect_kind(p,fo)=="archive":
                extract_archive(p,root/"files")
        except Exception as e:
            log(pid,f"extract error {p.name}: {e}")
    reports=[]
    analyzed=set()
    for pass_no in range(4):
        files=[p for p in all_files(root) if str(p) not in analyzed]
        if not files:
            break
        log(pid,f"StableWorkbench pass {pass_no+1}: {len(files)} files")
        total=max(1,len(files))
        for i,p in enumerate(files,1):
            analyzed.add(str(p))
            try:
                reports.append(analyze_file(pid,p,root,i,total))
            except Exception as e:
                reports.append({"id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":str(p.relative_to(root)),"kind":"error","error":str(e),"flags":[],"verified_flags":[],"strings":[],"outputs":[],"previews":[],"commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"artifacts":[],"findings":[{"score":20,"type":"analysis_error","value":str(e),"why":"File pipeline failed."}],"next_steps":[{"priority":20,"step":"Inspect manually; file pipeline failed.","why":str(e)}]})
            jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
        # Stop extra passes if we already have a promoted verified flag and no new promoted children.
        if any(r.get("flags") for r in reports) and not any(r.get("promoted_children") for r in reports[-total:]):
            break
    progress(pid,98,"Ranking evidence")
    jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    progress(pid,100,"Done")
    with LOCK:
        JOBS.setdefault(pid,{})["status"]="done"
def stableworkbench_public_verified(report):
    """Visible verified candidates: no duplicated fake/template spam."""
    out=[]
    seen=set()
    for v in sorted(report.get("verified_flags", []), key=lambda x:x.get("score",0), reverse=True):
        flag=(v.get("flag") or "").strip()
        if not flag:
            continue
        key=flag.lower()
        if key in seen:
            continue
        seen.add(key)
        if v.get("negative_reasons"):
            # Keep only one downgraded candidate if it is still very strong and exact-looking;
            # hide obvious sample/template noise by default.
            if is_noisy_candidate_text(flag, ";".join(v.get("negative_reasons", [])), "verified"):
                continue
            if v.get("score",0) < 220:
                continue
        if v.get("status") == "low":
            continue
        out.append(v)
    return out[:80]
def rank_findings(report):
    fs=[]
    for v in stableworkbench_public_verified(report)[:20]:
        fs.append({"score":v.get("score",0)+80,"type":"verified_flag_candidate:"+v.get("status",""),"value":v.get("flag",""),"why":"; ".join((v.get("reasons",[]) or [])[:3])})
    text="\n".join(report.get("strings",[])[:800])+"\n"+"\n".join((o.get("out") or "")[:8000] for o in report.get("outputs",[]))
    for hit in extract_flagish_text(text):
        if not is_noisy_candidate_text(hit.get("value",""), hit.get("why",""), hit.get("type","")):
            fs.append({"score":hit["score"],"type":hit["type"],"value":hit["value"],"why":hit["why"]})
    for f in report.get("flags",[]):
        if not is_noisy_candidate_text(f,"","promoted"):
            fs.append({"score":360,"type":"promoted_verified_flag","value":f,"why":"Verified likely/confirmed flag candidate."})
    for c in report.get("chain_results",[])[:60]:
        out=(c.get("output","") or "")[:800]
        if c.get("score",0)>70 and not is_noisy_candidate_text(out, c.get("type",""), "chain"):
            fs.append({"score":min(260,c.get("score",0)),"type":"chain:"+str(c.get("type","")),"value":out,"why":"From "+str(c.get("chain_source","unknown"))})
    for a in report.get("agent_runs",[])[:25]:
        fs.append({"score":a.get("score",0),"type":"agent:"+a.get("agent","agent"),"value":a.get("title","")+" :: "+a.get("why",""),"why":"Agent workflow recommendation."})
    for p in report.get("previews",[])[:18]:
        val=f"{p.get('name')} :: {(p.get('qr') or p.get('ocr') or '')[:650]}"
        if (p.get("score",0)>10 or p.get("ocr") or p.get("qr")) and not is_noisy_candidate_text(val,"","preview"):
            fs.append({"score":min(230,p.get("score",0)),"type":"ranked_image_filter","value":val,"why":"OCR/QR over generated filter/bitplane."})
    wf={"image":("image/stego workflow","Preview rank, zsteg, binwalk, OCR/QR, bitplanes.",80),"pcap":("network workflow","HTTP/DNS/TCP streams, exported files, decoders.",80),"binary":("reverse workflow","strings/braces, rabin2/r2, UPX, encoded blobs.",78),"archive":("archive workflow","children/comments/names/password hints.",72),"pdf":("pdf workflow","text/images/attachments/metadata.",72),"media":("media workflow","spectrogram/metadata/reverse audio.",70)}
    if report.get("kind") in wf:
        typ,why,score=wf[report["kind"]]; fs.append({"score":score,"type":typ,"value":report.get("rel"),"why":why})
    out=[]; seen=set()
    for f in sorted(fs,key=lambda x:x.get("score",0),reverse=True):
        k=(f.get("type"),f.get("value","")[:260])
        if k not in seen:
            seen.add(k); out.append(f)
    return out[:100]
def stableworkbench_apply_report_postprocess(report, root=None):
    try:
        apply_verified_flags(report)
    except Exception:
        pass
    good=[]
    for v in report.get("verified_flags", []):
        if v.get("status") in PROMOTED_STATUSES and not v.get("negative_reasons"):
            flag=v.get("flag","")
            if not is_noisy_candidate_text(flag,"","verified"):
                good.append(flag)
    report["flags"]=list(dict.fromkeys(good))[:30]
    report["verified_flags_visible"]=stableworkbench_public_verified(report)
    cleaned=[]
    for f in report.get("findings", []):
        if not is_noisy_candidate_text(f.get("value",""), f.get("why",""), f.get("type","")):
            cleaned.append(f)
    report["findings"]=sorted(cleaned,key=lambda x:x.get("score",0),reverse=True)[:100]
    report["artifacts"]=stableworkbench_artifacts_for_report(report)
    return report
def project_summary(reports, meta):
    flags=[]; verified_map={}; kinds={}; evidence=[]; chains=[]; actions=[]; missing=[]; agents=[]; transforms=[]; verifyloops=[]; artifacts=[]
    for r in reports:
        stableworkbench_apply_report_postprocess(r)
        kinds[r.get("kind","?")]=kinds.get(r.get("kind","?"),0)+1
        for v in r.get("verified_flags_visible", []):
            flag=(v.get("flag") or "").strip()
            if not flag:
                continue
            key=flag.lower()
            vv={"file":r.get("rel"),**v}
            old=verified_map.get(key)
            if old is None or vv.get("score",0)>old.get("score",0):
                verified_map[key]=vv
        for v in r.get("verified_flags", []):
            if v.get("status") in PROMOTED_STATUSES and not v.get("negative_reasons") and not is_noisy_candidate_text(v.get("flag",""),"","verified"):
                flags.append({"file":r.get("rel"),"flag":v.get("flag"),"score":v.get("score",0),"status":v.get("status")})
        for f in r.get("findings",[])[:60]:
            if not is_noisy_candidate_text(f.get("value",""), f.get("why",""), f.get("type","")):
                evidence.append({"file":r.get("rel"),**f})
        for c in r.get("chain_results",[])[:35]:
            out=(c.get("output","") or "")[:900]
            if c.get("score",0)>70 and not is_noisy_candidate_text(out,c.get("type",""),"chain"):
                chains.append({"file":r.get("rel"),"type":c.get("type"),"source":c.get("chain_source"),"score":c.get("score"),"output":out})
        for s in r.get("next_steps",[])[:10]:
            actions.append({"file":r.get("rel"),**s})
        for a in r.get("agent_runs",[])[:12]:
            agents.append({"file":r.get("rel"),"kind":r.get("kind"),**a})
        for t in r.get("transformations",[])[:50]:
            transforms.append({"file":r.get("rel"),**t})
        if r.get("verifyloop"):
            verifyloops.append({"file":r.get("rel"),"kind":r.get("kind"),**r.get("verifyloop",{})})
        for art in r.get("artifacts",[])[:180]:
            artifacts.append(art)
        for o in r.get("outputs",[]):
            if not o.get("ok") and "not installed" in (o.get("out","").lower()):
                missing.append((o.get("out","").split() or ["unknown"])[0])

    # Deduplicate promoted flags by flag string.
    flag_map={}
    for f in flags:
        key=(f.get("flag") or "").lower()
        if key and (key not in flag_map or f.get("score",0)>flag_map[key].get("score",0)):
            flag_map[key]=f
    flags=sorted(flag_map.values(),key=lambda x:x.get("score",0),reverse=True)[:60]
    verified_all=sorted(verified_map.values(),key=lambda x:x.get("score",0),reverse=True)[:100]
    evidence=sorted(evidence,key=lambda x:x.get("score",0),reverse=True)[:120]
    chains=sorted(chains,key=lambda x:x.get("score",0) or 0,reverse=True)[:90]
    artifacts=sorted(artifacts,key=lambda x:(x.get("exists",False),x.get("score",0),x.get("size",0)),reverse=True)[:650]
    exact=[f for f in flags if "ctf_cs{" in f.get("flag","").lower()]
    workflow=[]
    if exact:
        workflow.append({"priority":100,"step":"Submit/check top verified ctf_cs candidate.","why":"Candidate survived noise filters and has supporting sources."})
    elif verified_all:
        workflow.append({"priority":92,"step":"Open Verified Flags; inspect possible candidates manually.","why":"Candidates exist, but none were promoted enough for automatic trust."})
    if artifacts:
        workflow.append({"priority":90,"step":"Open Artifacts browser.","why":"All generated/transformed/extracted files are collected with open/copy controls."})
    if evidence:
        workflow.append({"priority":88,"step":"Open Evidence Board top item.","why":"Noisy template/sample candidates are hidden."})
    if chains:
        workflow.append({"priority":84,"step":"Open Chain Results for "+chains[0].get("file",""),"why":"Best derived output after noise filtering."})
    if not workflow:
        workflow.append({"priority":50,"step":"Open Files → priority file → Artifacts/Tools.","why":"No strong signal yet."})
    priority=sorted([{"file":r.get("rel"),"kind":r.get("kind"),"flags":len(r.get("flags",[])),"verified":len(r.get("verified_flags_visible",[])),"artifacts":len(r.get("artifacts",[])),"findings":len(r.get("findings",[])),"chains":len(r.get("chain_results",[])),"top_score":max([x.get("score",0) for x in r.get("findings",[])]+[0])} for r in reports],key=lambda x:(x["flags"],x["verified"],x["top_score"],x["artifacts"]),reverse=True)[:120]
    return {"flags":flags,"verified_flags":verified_all,"exact_flags":exact,"kinds":kinds,"evidence_board":evidence,"top_findings":evidence,"top_chains":chains,"agents":sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:160],"transformations":sorted(transforms,key=lambda x:x.get("score",0),reverse=True)[:240],"artifacts":artifacts,"verifyloops":verifyloops[:160],"hypotheses":workflowbrain_project_hypotheses(reports) if "workflowbrain_project_hypotheses" in globals() else [],"workflow_steps":sorted(workflow+actions,key=lambda x:x.get("priority",0),reverse=True)[:160],"missing_tools":sorted(set(missing))[:100],"priority_files":priority}
SMARTSOLVE_NOISE_WORDS = set(FALSE_FLAG_WORDS + ["sample_test", "sample", "example", "template", "dummy_test", "smoke", "format"])
def smartsolve_clean_verified_list(report):
    """Ultra-visible list: only real-looking candidates, deduped hard."""
    out, seen = [], set()
    for v in sorted(report.get("verified_flags", []), key=lambda x:x.get("score",0), reverse=True):
        flag = (v.get("flag") or "").strip()
        if not flag:
            continue
        low = flag.lower()
        inner = flag_inner(flag).lower()
        if low in seen:
            continue
        seen.add(low)
        if any(w in inner for w in SMARTSOLVE_NOISE_WORDS):
            continue
        if v.get("negative_reasons"):
            continue
        if v.get("status") not in ["confirmed", "likely"]:
            continue
        if not low.startswith("ctf_cs{"):
            continue
        out.append(v)
    return out[:25]
def smartsolve_candidate_health(report):
    total = len(report.get("verified_flags", []))
    visible = len(smartsolve_clean_verified_list(report))
    negatives = sum(1 for v in report.get("verified_flags", []) if v.get("negative_reasons"))
    promoted = len(report.get("flags", []))
    return {
        "total_raw_candidates": total,
        "visible_verified_candidates": visible,
        "negative_or_noisy_candidates": negatives,
        "promoted_flags": promoted,
        "noise_ratio": round(negatives / max(1, total), 3)
    }
def smartsolve_make_brief(root, report):
    """Create a concise solver brief artifact for humans/local AI."""
    outdir = root / "generated" / "smartsolve_briefs"
    outdir.mkdir(parents=True, exist_ok=True)
    brief = {
        "file": report.get("rel"),
        "kind": report.get("kind"),
        "promoted_flags": report.get("flags", []),
        "verified_candidates": smartsolve_clean_verified_list(report),
        "candidate_health": smartsolve_candidate_health(report),
        "top_findings": report.get("findings", [])[:12],
        "top_chains": report.get("chain_results", [])[:10],
        "top_artifacts": report.get("artifacts", [])[:30],
        "recipes": report.get("recipe_runs", [])[:12],
        "next_steps": report.get("next_steps", [])[:12],
    }
    p = outdir / (safe(report.get("name","file")) + ".smartsolve.json")
    try:
        p.write_text(json.dumps(brief, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"kind":"solver_brief","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"SmartSolve brief","score":95,"note":"Concise solve summary for human/local AI","exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
    except Exception:
        return None
def smartsolve_artifact_graph(report):
    """Small artifact graph so the user can see where files came from."""
    nodes = []
    edges = []
    seen = set()
    def node(node_id, label, kind, path="", score=0):
        if node_id in seen:
            return
        seen.add(node_id)
        nodes.append({"id":node_id,"label":label,"kind":kind,"path":path,"score":score})
    root_id = "file:" + report.get("rel","root")
    node(root_id, report.get("rel","file"), "original", report.get("path",""), 100)
    for i,a in enumerate(report.get("artifacts", [])[:160]):
        aid = "artifact:" + str(i) + ":" + a.get("path","")
        node(aid, a.get("name") or Path(a.get("path","")).name, a.get("kind","artifact"), a.get("path",""), a.get("score",0))
        edges.append({"from":root_id,"to":aid,"label":a.get("source","generated")})
    for i,c in enumerate(report.get("chain_results", [])[:30]):
        cid = "chain:" + str(i)
        node(cid, c.get("type","chain"), "chain", "", c.get("score",0))
        edges.append({"from":root_id,"to":cid,"label":c.get("chain_source","decoder")})
    return {"nodes":nodes[:180],"edges":edges[:220]}
def smartsolve_recipe_engine(report, root):
    """Recipe ranking based on real CTF solve patterns."""
    recipes=[]
    kind = report.get("kind","generic")
    text = "\n".join(report.get("strings",[])[:900]) + "\n" + "\n".join((o.get("out") or "")[:4000] for o in report.get("outputs",[])[:30])
    low = text.lower()
    def add(name, score, why, actions, artifact_kinds=None):
        arts = []
        for a in report.get("artifacts", [])[:200]:
            if not artifact_kinds or any(k in a.get("kind","") for k in artifact_kinds):
                arts.append(a)
        recipes.append({"name":name,"score":int(score),"why":why,"actions":actions,"artifacts":arts[:20]})
    if kind == "image":
        add("image_lsb_visual", 90, "Image challenge: filters/bitplanes/LSB/OCR/QR are high-value first.", ["Open Artifacts → preview/contact sheet", "Open Preview top tiles", "Check LSB decoded text", "Run zsteg_all if installed"], ["preview","image","decoded"])
        if "zip" in low or "archive" in low or "binwalk" in low:
            add("image_payload", 86, "Image output suggests embedded or appended payload.", ["Open Artifacts → archive_child/promoted_child", "Run binwalk_extract/foremost manually if needed"], ["archive","promoted","transformation"])
    elif kind == "pcap":
        add("pcap_exfil", 92, "PCAP solve path: protocol stats, HTTP objects, DNS labels, TCP streams.", ["Open Artifacts → pcap_tcp_stream/pcap_dns/pcap_exported_object", "Open Chain results from streams", "Decode suspicious labels"], ["pcap"])
    elif kind == "binary":
        add("binary_string_decrypt", 90, "Reverse task: string/rodata/imports often reveal encoded constants or validation logic.", ["Open Artifacts → binary_dump", "Open Chain top results", "Run rabin2_strings/r2_info manually if available"], ["binary","decoded","xor"])
        if "upx" in low or "packed" in low:
            add("binary_unpack", 88, "Packing/UPX indicator present.", ["Open UPX artifacts/logs", "Analyze unpacked child if created"], ["unpacked"])
    elif kind in ["text","generic"]:
        if any(x in low for x in ["rsa","n=","e=","c="]):
            add("crypto_rsa_params", 88, "RSA-like parameters detected.", ["Open Artifacts → rsa_parameters.json", "Ask local AI for attack classification", "Use local RsaCtfTool manually if installed"], ["rsa"])
        if any(x in low for x in ["eyj", "jwt"]):
            add("jwt_decode", 82, "JWT-like token detected.", ["Open JWT artifacts", "Decode header/payload", "Check alg/claims"], ["jwt"])
        add("crypto_encoding_stack", 84, "Text/generic task: recursive encoding/XOR/decompression stack likely.", ["Open Chain", "Open decoded/xor artifacts", "Use Decoder Lab on top blob"], ["decoded","xor","blob","decompress"])
    elif kind == "pdf":
        add("pdf_layers", 88, "PDF tasks often hide flags in text layer, attachments, images, or metadata.", ["Open PDF artifacts", "Inspect attachments/images", "Run OCR on extracted images"], ["pdf"])
    elif kind == "archive":
        add("archive_nested", 88, "Archive tasks often use nested files, comments, child artifacts, or password hints.", ["Open archive_child artifacts", "Inspect comments/listing", "Analyze child files"], ["archive","promoted"])
    elif kind == "media":
        add("media_signal", 84, "Media tasks often use metadata, spectrograms, or appended data.", ["Open spectrogram artifact", "Inspect strings/binwalk artifacts", "Decode any text"], ["media","preview"])
    elif kind in ["sqlite","apk","python_bytecode"]:
        add("structured_artifact", 84, "Structured artifact should be decompiled/queried and searched for constants.", ["Open schema/decompile artifacts", "Search generated files", "Check Chain"], ["decoded","strings","artifact"])
    if report.get("flags"):
        add("verified_submit", 100, "A promoted verified flag exists.", ["Copy promoted flag from Summary/Verified Flags", "Check if challenge accepts it"], [])
    if not recipes:
        add("generic_triage", 55, "No strong recipe matched; use artifacts and chain first.", ["Open Artifacts", "Open Chain", "Run manual Deep Suite"], [])
    return sorted(recipes, key=lambda x:x.get("score",0), reverse=True)[:18]
def smartsolve_postprocess(report, root=None):
    if root is None:
        root = BASE
    stableworkbench_apply_report_postprocess(report, root)
    report["verified_flags_visible"] = smartsolve_clean_verified_list(report)
    report["candidate_health"] = smartsolve_candidate_health(report)
    report["recipe_runs"] = smartsolve_recipe_engine(report, root)
    brief = smartsolve_make_brief(root, report)
    if brief:
        report.setdefault("artifacts", [])
        if not any(a.get("path") == brief["path"] for a in report["artifacts"]):
            report["artifacts"].insert(0, brief)
    report["artifact_graph"] = smartsolve_artifact_graph(report)
    # Re-clean findings after recipe/brief addition.
    cleaned = []
    for f in report.get("findings", []):
        if not is_noisy_candidate_text(f.get("value",""), f.get("why",""), f.get("type","")):
            cleaned.append(f)
    report["findings"] = sorted(cleaned, key=lambda x:x.get("score",0), reverse=True)[:90]
    return report
def analyze_file(pid,path,root,i,total):
    progress(pid,min(94,int((i/max(1,total))*84)+6),f"Analyzing {path.name}")
    data=readbytes(path)
    fileout=run(["file",str(path)],8).get("out","") if exists("file") else ""
    kind=detect_kind(path,fileout)
    ss=py_strings(data)
    rep={"id":uuid.uuid4().hex[:10],"name":path.name,"path":str(path),"rel":str(path.relative_to(root)),"size":path.stat().st_size,"entropy":entropy(data[:2_000_000]),"kind":kind,"file":fileout,"fingerprint":{"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest()},"flags":list(dict.fromkeys(x.decode("utf-8","replace") for x in FLAG_BYTES_RE.findall(data))),"strings":ss[:900],"outputs":[],"previews":[],"commands":[],"extracted":[],"expert_contexts":[],"decoders":[],"chain_results":[],"intermediate_files":[],"findings":[],"next_steps":[],"hypotheses":[],"structured_clues":[],"agent_runs":[],"agent_files":[],"transformations":[],"verifyloop":{},"verified_flags":[],"promoted_children":[],"artifacts":[],"recipe_runs":[],"artifact_graph":{},"candidate_health":{}}
    if kind=="archive":
        rep["extracted"]=extract_archive(path,root/"files")
    if kind=="image":
        pv,outs=image_lab(path,root)
        rep["previews"]+=pv
        rep["outputs"]+=outs
        for v in pv:
            for f in v.get("flags",[]):
                if f not in rep["flags"]:
                    rep["flags"].append(f)
    if kind=="media" and exists("ffmpeg"):
        spdir=root/"generated"/"media"/path.stem
        spdir.mkdir(parents=True,exist_ok=True)
        sp=spdir/"spectrogram.png"
        r=run(["ffmpeg","-y","-i",str(path),"-lavfi","showspectrumpic=s=1600x900",str(sp)],45)
        rep["outputs"].append({"tool":"spectrogram","ok":r["ok"],"cmd":r["cmd"],"out":r["out"]})
        if sp.exists():
            rep["previews"].append({"name":"spectrogram","url":"/api/raw?path="+str(sp),"path":str(sp),"score":15})
    for label,tpl,to in PIPE["common"]+PIPE.get(kind,[]):
        if label in ["objdump","readelf","r2 quick"] and kind!="binary":
            continue
        cmd=make_cmd(tpl,path)
        rep["commands"].append(" ".join(cmd))
        if cmd[0] not in ["bash","sh"] and not exists(cmd[0]):
            rep["outputs"].append({"tool":label,"ok":False,"cmd":" ".join(cmd),"out":cmd[0]+" not installed"})
            continue
        r=run(cmd,min(to,45))
        rep["outputs"].append({"tool":label,"ok":r["ok"],"cmd":r["cmd"],"out":r["out"]})
        for mf in fast_flag_matches(r.get("out",""), limit=20):
            if mf not in rep["flags"]:
                rep["flags"].append(mf)
    rep["verifyloop"]=verifyloop_run_tools(pid,path,rep,root)
    verifyloop_refresh_analysis(rep,data)
    rep["transformations"]=execute_transform_agents(rep,root,data)
    rep["intermediate_files"]=(rep.get("intermediate_files",[])+rep.get("transformations",[]))[:320]
    write_intermediate_files(rep,root)
    rep["agent_runs"],rep["agent_files"]=run_agent_forge(rep,root)
    rep["intermediate_files"]=(rep.get("intermediate_files",[])+rep.get("agent_files",[]))[:320]
    verifyloop_scan_transform_files(rep)
    verifyloop_refresh_analysis(rep,data)
    apply_verified_flags(rep)
    verifyloop_promote_artifacts(root,rep)
    rep["findings"]=rank_findings(rep)
    rep["next_steps"]=next_steps(rep)
    smartsolve_postprocess(rep,root)
    return rep
def project_summary(reports, meta):
    flags=[]; verified_map={}; kinds={}; evidence=[]; chains=[]; actions=[]; missing=[]; agents=[]; transforms=[]; verifyloops=[]; artifacts=[]; recipes=[]; graphs=[]
    for r in reports:
        stableworkbench_apply_report_postprocess(r)
        kinds[r.get("kind","?")]=kinds.get(r.get("kind","?"),0)+1
        for v in r.get("verified_flags_visible", []):
            key=(v.get("flag") or "").lower()
            vv={"file":r.get("rel"),**v}
            if key and (key not in verified_map or vv.get("score",0)>verified_map[key].get("score",0)):
                verified_map[key]=vv
        for f in r.get("flags", []):
            if not is_noisy_candidate_text(f,"","promoted"):
                flags.append({"file":r.get("rel"),"flag":f,"score":999,"status":"promoted"})
        for f in r.get("findings",[])[:60]:
            if not is_noisy_candidate_text(f.get("value",""), f.get("why",""), f.get("type","")):
                evidence.append({"file":r.get("rel"),**f})
        for c in r.get("chain_results",[])[:30]:
            out=(c.get("output","") or "")[:900]
            if c.get("score",0)>70 and not is_noisy_candidate_text(out,c.get("type",""),"chain"):
                chains.append({"file":r.get("rel"),"type":c.get("type"),"source":c.get("chain_source"),"score":c.get("score"),"output":out})
        for s in r.get("next_steps",[])[:10]:
            actions.append({"file":r.get("rel"),**s})
        for a in r.get("agent_runs",[])[:12]:
            agents.append({"file":r.get("rel"),"kind":r.get("kind"),**a})
        for t in r.get("transformations",[])[:50]:
            transforms.append({"file":r.get("rel"),**t})
        if r.get("verifyloop"):
            verifyloops.append({"file":r.get("rel"),"kind":r.get("kind"),**r.get("verifyloop",{})})
        for art in r.get("artifacts",[])[:220]:
            artifacts.append(art)
        for rec in r.get("recipe_runs",[])[:12]:
            recipes.append({"file":r.get("rel"),"kind":r.get("kind"),**rec})
        if r.get("artifact_graph"):
            graphs.append({"file":r.get("rel"),"graph":r.get("artifact_graph")})
        for o in r.get("outputs",[]):
            if not o.get("ok") and "not installed" in (o.get("out","").lower()):
                missing.append((o.get("out","").split() or ["unknown"])[0])
    # Dedupe flags.
    flag_map={}
    for f in flags:
        key=(f.get("flag") or "").lower()
        if key and (key not in flag_map or f.get("score",0)>flag_map[key].get("score",0)):
            flag_map[key]=f
    flags=sorted(flag_map.values(),key=lambda x:x.get("score",0),reverse=True)[:60]
    verified_all=sorted(verified_map.values(),key=lambda x:x.get("score",0),reverse=True)[:80]
    evidence=sorted(evidence,key=lambda x:x.get("score",0),reverse=True)[:120]
    chains=sorted(chains,key=lambda x:x.get("score",0) or 0,reverse=True)[:90]
    artifacts=sorted(artifacts,key=lambda x:(x.get("exists",False),x.get("score",0),x.get("size",0)),reverse=True)[:700]
    recipes=sorted(recipes,key=lambda x:x.get("score",0),reverse=True)[:140]
    exact=[f for f in flags if "ctf_cs{" in f.get("flag","").lower()]
    workflow=[]
    if exact:
        workflow.append({"priority":100,"step":"Submit/check top SmartSolve verified flag.","why":"Candidate survived noise filters and recipe verification."})
    elif verified_all:
        workflow.append({"priority":92,"step":"Open Verified Flags; inspect likely candidates.","why":"Candidates exist, but none were promoted enough for automatic trust."})
    if recipes:
        workflow.append({"priority":91,"step":"Open Recipes tab and follow top recipe.","why":"Recipe Engine picked solve paths from artifact/tool signals."})
    if artifacts:
        workflow.append({"priority":90,"step":"Open Artifacts browser.","why":"Generated/transformed/extracted files are collected with open/copy controls."})
    if evidence:
        workflow.append({"priority":88,"step":"Open Evidence Board top item.","why":"Noisy template/sample candidates are hidden."})
    if not workflow:
        workflow.append({"priority":50,"step":"Open Files → priority file → Artifacts/Tools.","why":"No strong signal yet."})
    priority=sorted([{"file":r.get("rel"),"kind":r.get("kind"),"flags":len(r.get("flags",[])),"verified":len(r.get("verified_flags_visible",[])),"recipes":len(r.get("recipe_runs",[])),"artifacts":len(r.get("artifacts",[])),"findings":len(r.get("findings",[])),"chains":len(r.get("chain_results",[])),"top_score":max([x.get("score",0) for x in r.get("findings",[])]+[0])} for r in reports],key=lambda x:(x["flags"],x["verified"],x["recipes"],x["top_score"],x["artifacts"]),reverse=True)[:120]
    return {"flags":flags,"verified_flags":verified_all,"exact_flags":exact,"kinds":kinds,"evidence_board":evidence,"top_findings":evidence,"top_chains":chains,"agents":sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:160],"transformations":sorted(transforms,key=lambda x:x.get("score",0),reverse=True)[:240],"artifacts":artifacts,"recipes":recipes,"artifact_graphs":graphs[:120],"verifyloops":verifyloops[:160],"hypotheses":workflowbrain_project_hypotheses(reports) if "workflowbrain_project_hypotheses" in globals() else [],"workflow_steps":sorted(workflow+actions,key=lambda x:x.get("priority",0),reverse=True)[:160],"missing_tools":sorted(set(missing))[:100],"priority_files":priority}
