# Auto-split from sloper_legacy_monolith.py lines 897-...
def agent_transform_archive(report, root, raw):
    out=[]
    src=Path(report.get("path",""))
    if not src.exists(): return out
    base=root/"generated"/"verifyloop"/safe(report.get("name","file"))/"archive_agent"
    base.mkdir(parents=True, exist_ok=True)
    if exists("7z"):
        extract_dir=base/"seven_extract"; extract_dir.mkdir(exist_ok=True)
        r=run(["7z","x",str(src),"-o"+str(extract_dir),"-y"],120)
        logp=base/"7z_extract.log"
        tf_safe_write(logp, r.get("out",""))
        out.append(transform_record("archive_extract_log", logp.name, logp, "7z extract", score_text(r.get("out","")), "7z extraction log"))
        for f in extract_dir.rglob("*"):
            if f.is_file():
                out.append(transform_record("archive_child", f.name, f, "7z extracted child", 55, "File extracted from archive"))
    return out[:160]
def agent_transform_binary(report, root, raw):
    out=[]
    src=Path(report.get("path",""))
    if not src.exists(): return out
    base=root/"generated"/"verifyloop"/safe(report.get("name","file"))/"binary_agent"
    base.mkdir(parents=True, exist_ok=True)
    # dump strings already from Python, plus local tool outputs when available
    for name, cmd, desc in [
        ("strings_ascii.txt", ["strings","-a",str(src)], "ASCII strings"),
        ("strings_utf16.txt", ["strings","-el",str(src)], "UTF-16 strings"),
        ("rodata.txt", ["bash","-lc",f"objdump -s -j .rodata {str(src)!r} 2>/dev/null | head -2000"], "rodata dump"),
        ("rabin2_strings.txt", ["rabin2","-zz",str(src)], "rabin2 strings")
    ]:
        if cmd[0]=="bash" or exists(cmd[0]):
            r=run(cmd,90)
            p=base/name
            if tf_safe_write(p,r.get("out","")):
                out.append(transform_record("binary_dump", p.name, p, desc, score_text(r.get("out","")), desc))
    if exists("upx"):
        outp=base/(src.name+".upx_unpacked")
        r=run(["upx","-d",str(src),"-o",str(outp)],120)
        logp=base/"upx_decompress.log"
        tf_safe_write(logp,r.get("out",""))
        out.append(transform_record("upx_log", logp.name, logp, "upx decompress", score_text(r.get("out","")), "UPX decompression attempt log"))
        if outp.exists():
            out.append(transform_record("binary_unpacked", outp.name, outp, "upx decompressed binary", 70, "UPX unpacked output"))
    return out[:160]
def agent_transform_crypto_text(report, root, raw):
    out=[]
    base=root/"generated"/"verifyloop"/safe(report.get("name","file"))/"crypto_text_agent"
    base.mkdir(parents=True, exist_ok=True)
    text="\n".join(report.get("strings",[])[:2400])+"\n"+"\n".join((o.get("out") or "")[:9000] for o in report.get("outputs",[]))
    clues=detect_structured_clues(text) if "detect_structured_clues" in globals() else []
    rsa=[c for c in clues if str(c.get("type","")).startswith("rsa_parameter")]
    if rsa:
        p=base/"rsa_parameters.json"
        if tf_safe_write(p,json.dumps(rsa,ensure_ascii=False,indent=2)):
            out.append(transform_record("rsa_params", p.name, p, "RSA parameter extractor", 85, "RSA-like parameters structured as JSON"))
    jwt=[c for c in clues if c.get("type")=="jwt_token"]
    if jwt:
        p=base/"jwt_candidates.json"
        if tf_safe_write(p,json.dumps(jwt,ensure_ascii=False,indent=2)):
            out.append(transform_record("jwt_candidates", p.name, p, "JWT extractor", 75, "JWT candidates structured as JSON"))
    hashes=[c for c in clues if "hash" in c.get("type","")]
    if hashes:
        p=base/"hash_candidates.txt"
        if tf_safe_write(p,"\n".join(c.get("value","") for c in hashes)):
            out.append(transform_record("hash_candidates", p.name, p, "hash extractor", 60, "Hash-looking values"))
    return out
def execute_transform_agents(report, root, raw):
    """Run actual local transformations and materialize artifacts. Safe, bounded, local-only."""
    results=[]
    kind=report.get("kind","generic")
    results += agent_transform_generic(report, root, raw)
    results += agent_transform_crypto_text(report, root, raw)
    if kind=="image": results += agent_transform_image(report, root, raw)
    if kind=="pcap": results += agent_transform_pcap(report, root, raw)
    if kind=="pdf": results += agent_transform_pdf(report, root, raw)
    if kind=="archive": results += agent_transform_archive(report, root, raw)
    if kind=="binary": results += agent_transform_binary(report, root, raw)
    # dedupe
    out=[]; seen=set()
    for r in sorted(results,key=lambda x:x.get("score",0), reverse=True):
        k=(r.get("kind"),r.get("path"))
        if k not in seen:
            seen.add(k); out.append(r)
    return out[:320]
def verifyloop_output_key(o):
    return (str(o.get("tool","")), str(o.get("cmd",""))[:240])
def verifyloop_add_outputs(report, outputs):
    seen = {verifyloop_output_key(o) for o in report.get("outputs", [])}
    added = []
    for o in outputs:
        k = verifyloop_output_key(o)
        if k in seen:
            continue
        seen.add(k)
        report.setdefault("outputs", []).append(o)
        added.append(o)
    return added
def verifyloop_relevant_tools(path, kind):
    """Aggressive but bounded automatic tools per file type."""
    tools = []
    # always include quick + deep suites from tool routing
    try:
        _, q = suite_for_path(path, "quick")
        _, d = suite_for_path(path, "deep")
        tools += q + d
    except Exception:
        pass

    generic_extra = [
        "file", "magic_bytes", "sha256sum", "md5sum", "strings", "strings_braces",
        "strings_utf16", "extract_ascii_context", "grep_crypto_clues", "grep_urls_tokens",
        "rg_project", "xxd_head", "xxd_tail", "exiftool", "binwalk", "binwalk_extract",
        "foremost", "yara_basic", "find_files_nearby"
    ]
    type_extra = {
        "image": [
            "identify", "image_magick_info", "pngcheck", "png_chunks", "zsteg_all",
            "stegseek", "steghide_info", "steghide_extract_empty", "tesseract",
            "zbarimg", "binwalk_recursive"
        ],
        "pcap": [
            "capinfos", "tshark_protocols", "tshark_http", "tshark_dns",
            "tshark_tcp0", "tshark_tcp1", "tshark_tcp2", "tshark_files",
            "binwalk_recursive"
        ],
        "pdf": [
            "pdfinfo", "pdftotext", "pdfimages", "pdfdetach_list", "pdfdetach_extract",
            "qpdf_check", "binwalk_recursive"
        ],
        "archive": [
            "seven_list", "zipinfo", "zip_comment", "hashid_file", "binwalk_recursive"
        ],
        "binary": [
            "readelf", "elf_sections", "elf_imports", "checksec_basic",
            "rabin2_info", "rabin2_strings", "r2_info", "upx_test", "upx_decompress",
            "objdump", "objdump_rodata", "nm", "ltrace_short", "strace_short"
        ],
        "media": ["ffprobe", "soxi", "spectrogram"],
        "sqlite": ["sqlite_tables", "sqlite_schema"],
        "apk": ["apktool_decode", "jadx_decompile"],
        "python_bytecode": ["python_pyc_decompile", "decompyle3"],
        "text": ["grep_crypto_clues", "grep_urls_tokens", "strings_utf16", "hashid_file"],
        "generic": ["grep_crypto_clues", "grep_urls_tokens", "hashid_file"]
    }
    tools += generic_extra + type_extra.get(kind, type_extra.get("generic", []))
    # Dedupe, keep existing command-backed only
    out, seen = [], set()
    for t in tools:
        if t in TOOL_COMMANDS and t not in seen:
            seen.add(t)
            out.append(t)
    return out[:90]
def verifyloop_run_tools(pid, path, report, root):
    """Automatically run all relevant local tools for the file and return clean outputs."""
    kind = report.get("kind", "generic")
    tools = verifyloop_relevant_tools(path, kind)
    results = []
    total = max(1, len(tools))
    log(pid, f"VerifyLoop: {path.name} kind={kind} tools={len(tools)}")
    for i, tool in enumerate(tools, 1):
        try:
            # keep slow/deep tools bounded; missing tools produce clean cards
            r = run_tool_local(path, tool, 180)
            r["auto"] = True
            r["tool"] = "verifyloop:" + tool
            results.append(r)
            report.setdefault("commands", []).append(r.get("cmd",""))
            # immediate exact flag capture from each tool
            for ev in r.get("evidence", []) or []:
                val = ev.get("value","")
                if "ctf_cs{" in val.lower() and val not in report.setdefault("flags", []):
                    report["flags"].append(val)
            for d in r.get("decoders", []) or []:
                for f in d.get("flags", []) or []:
                    if f not in report.setdefault("flags", []):
                        report["flags"].append(f)
        except Exception as e:
            results.append({"tool":"verifyloop:"+tool,"ok":False,"cmd":tool,"out":"VerifyLoop tool failed: "+str(e),"auto":True})
    added = verifyloop_add_outputs(report, results)
    return {"tools": tools, "added_outputs": len(added), "results": results}
def verifyloop_refresh_analysis(report, raw_data):
    """After tools/transforms, rebuild contexts, decoders, chains, findings and steps."""
    outtxt = "\n".join((o.get("out") or "")[:10000] for o in report.get("outputs", []))
    combined = "\n".join(report.get("strings", [])[:2200]) + "\n" + outtxt
    report["expert_contexts"] = expert_context_lines(combined)
    report["decoders"] = sorted(
        decode_candidates(combined, raw_data) + recursive_decode_seed(combined),
        key=lambda x: x.get("score", 0),
        reverse=True
    )[:620]
    report["chain_results"] = chain_decode_report(report, raw_data)
    report["structured_clues"] = detect_structured_clues(
        combined + "\n" + "\n".join((c.get("output","") or "")[:4000] for c in report.get("chain_results", [])[:80])
    )
    report["hypotheses"] = classify_workflow_hypotheses(report)
    return report
def verifyloop_scan_transform_files(report):
    """Read transformation/intermediate text files and add their evidence/decoders to the report."""
    texts = []
    for item in (report.get("transformations", []) + report.get("intermediate_files", []) + report.get("agent_files", []))[:260]:
        p = Path(item.get("path",""))
        try:
            if p.exists() and p.is_file() and p.stat().st_size <= 2_000_000:
                if p.suffix.lower() in [".txt", ".json", ".log", ".agent", ".csv", ".xml", ".html", ".md"] or "strings" in p.name or "decoded" in p.name:
                    texts.append(p.read_text(encoding="utf-8", errors="ignore")[:20000])
        except Exception:
            pass
    if not texts:
        return
    text = "\n".join(texts)
    report.setdefault("outputs", []).append({
        "tool": "verifyloop:transformation_file_scan",
        "ok": True,
        "cmd": "internal scan generated transform/intermediate files",
        "out": text[:80000],
        "auto": True
    })
    for hit in extract_flagish_text(text):
        val = hit.get("value","")
        if "ctf_cs{" in val.lower() and val not in report.setdefault("flags", []):
            report["flags"].append(val)
def analyze_file(pid,path,root,i,total):
    progress(pid,min(94,int((i/total)*84)+6),f"Analyzing {path.name}")
    data=readbytes(path); fileout=run(["file",str(path)],20).get("out","") if exists("file") else ""; kind=detect_kind(path,fileout); ss=py_strings(data)
    rep={"id":uuid.uuid4().hex[:10],"name":path.name,"path":str(path),"rel":str(path.relative_to(root)),"size":path.stat().st_size,"entropy":entropy(data[:2_000_000]),"kind":kind,"file":fileout,"fingerprint":{"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest()},"flags":list(dict.fromkeys(x.decode("utf-8","replace") for x in FLAG_BYTES_RE.findall(data))),"strings":ss[:900],"outputs":[],"previews":[],"commands":[],"extracted":[],"expert_contexts":[],"decoders":[],"chain_results":[],"intermediate_files":[],"findings":[],"next_steps":[],"hypotheses":[],"structured_clues":[],"agent_runs":[],"agent_files":[],"transformations":[],"verifyloop":{},"verified_flags":[],"promoted_children":[]}
    if kind=="archive": rep["extracted"]=extract_archive(path,root/"files")
    if kind=="image":
        pv,outs=image_lab(path,root); rep["previews"]+=pv; rep["outputs"]+=outs
        for v in pv:
            for f in v.get("flags",[]):
                if f not in rep["flags"]: rep["flags"].append(f)
    if kind=="media" and exists("ffmpeg"):
        spdir=root/"generated"/"media"/path.stem; spdir.mkdir(parents=True,exist_ok=True); sp=spdir/"spectrogram.png"
        r=run(["ffmpeg","-y","-i",str(path),"-lavfi","showspectrumpic=s=1600x900",str(sp)],90)
        rep["outputs"].append({"tool":"spectrogram","ok":r["ok"],"cmd":r["cmd"],"out":r["out"]})
        if sp.exists(): rep["previews"].append({"name":"spectrogram","url":"/api/raw?path="+str(sp),"path":str(sp),"score":15})
    for label,tpl,to in PIPE["common"]+PIPE.get(kind,[]):
        cmd=make_cmd(tpl,path); rep["commands"].append(" ".join(cmd))
        if cmd[0] not in ["bash","sh"] and not exists(cmd[0]):
            rep["outputs"].append({"tool":label,"ok":False,"cmd":" ".join(cmd),"out":cmd[0]+" not installed"}); continue
        r=run(cmd,to); rep["outputs"].append({"tool":label,"ok":r["ok"],"cmd":r["cmd"],"out":r["out"]})
        for mf in FLAG_TEXT_RE.findall(r.get("out","")):
            if mf not in rep["flags"]: rep["flags"].append(mf)
    rep["verifyloop"] = verifyloop_run_tools(pid, path, rep, root)
    verifyloop_refresh_analysis(rep, data)
    rep["transformations"] = execute_transform_agents(rep, root, data)
    rep["intermediate_files"] = (rep.get("intermediate_files",[]) + rep.get("transformations",[]))[:320]
    write_intermediate_files(rep,root)
    rep["agent_runs"], rep["agent_files"] = run_agent_forge(rep, root)
    rep["intermediate_files"] = (rep.get("intermediate_files",[]) + rep.get("agent_files",[]))[:320]
    verifyloop_scan_transform_files(rep)
    verifyloop_refresh_analysis(rep, data)
    apply_verified_flags(rep)
    verifyloop_promote_artifacts(root, rep)
    rep["findings"]=rank_findings(rep)
    rep["next_steps"]=next_steps(rep)
    return rep
def project_summary(reports,meta):
    flags=[]; verified_all=[]; kinds={}; evidence=[]; chains=[]; actions=[]; missing=[]; agents=[]; transforms=[]; verifyloops=[]
    for r in reports:
        kinds[r.get("kind","?")]=kinds.get(r.get("kind","?"),0)+1
        for v in r.get("verified_flags",[]):
            vv={"file":r.get("rel"),**v}; verified_all.append(vv)
            if v.get("status") in ["confirmed","likely"] and not v.get("negative_reasons"):
                flags.append({"file":r.get("rel"),"flag":v.get("flag"),"score":v.get("score",0),"status":v.get("status")})
        for f in r.get("findings",[])[:60]: evidence.append({"file":r.get("rel"),**f})
        for c in r.get("chain_results",[])[:30]:
            if c.get("score",0)>50: chains.append({"file":r.get("rel"),"type":c.get("type"),"source":c.get("chain_source"),"score":c.get("score"),"output":(c.get("output","") or "")[:900]})
        for s in r.get("next_steps",[])[:8]: actions.append({"file":r.get("rel"),**s})
        for a in r.get("agent_runs",[])[:12]: agents.append({"file":r.get("rel"),"kind":r.get("kind"),**a})
        for t in r.get("transformations",[])[:30]: transforms.append({"file":r.get("rel"),**t})
        if r.get("verifyloop"): verifyloops.append({"file":r.get("rel"),"kind":r.get("kind"),**r.get("verifyloop",{})})
        for o in r.get("outputs",[]):
            if not o.get("ok") and "not installed" in (o.get("out","").lower()): missing.append(o.get("out","").split()[0])
    exact=[f for f in flags if "ctf_cs{" in f.get("flag","").lower()]
    evidence=sorted(evidence,key=lambda x:x.get("score",0),reverse=True)[:220]; chains=sorted(chains,key=lambda x:x.get("score",0) or 0,reverse=True)[:140]
    workflow=[]
    if exact: workflow.append({"priority":100,"step":"Verify/submit top ctf_cs candidate.","why":"Exact target format found."})
    if evidence: workflow.append({"priority":95,"step":"Open Evidence Board top item.","why":"Highest scoring evidence across all files."})
    if chains: workflow.append({"priority":90,"step":"Open Chain Results for "+chains[0].get("file",""),"why":"Best derived output."})
    if not workflow: workflow.append({"priority":50,"step":"Open Files → priority file → Chain → Tools.","why":"No direct flag yet."})
    priority=sorted([{"file":r.get("rel"),"kind":r.get("kind"),"flags":len(r.get("flags",[])),"findings":len(r.get("findings",[])),"chains":len(r.get("chain_results",[])),"top_score":max([x.get("score",0) for x in r.get("findings",[])]+[0])} for r in reports],key=lambda x:(x["flags"],x["top_score"],x["chains"]),reverse=True)[:100]
    return {"flags":flags,"verified_flags":sorted(verified_all,key=lambda x:x.get("score",0),reverse=True)[:180],"exact_flags":exact,"kinds":kinds,"evidence_board":evidence,"top_findings":evidence,"top_chains":chains,"agents":sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:160],"transformations":sorted(transforms,key=lambda x:x.get("score",0),reverse=True)[:220],"verifyloops":verifyloops[:160],"hypotheses":workflowbrain_project_hypotheses(reports),"workflow_steps":sorted(workflow+actions,key=lambda x:x.get("priority",0),reverse=True)[:140],"missing_tools":sorted(set(missing))[:100],"priority_files":priority}
def ai_prompt(meta,reports):
    compact=[]
    for r in reports[:120]:
        compact.append({"file":r.get("rel"),"kind":r.get("kind"),"flags":r.get("flags"),"verified_flags":r.get("verified_flags",[])[:25],"promoted_children":r.get("promoted_children",[])[:25],"findings":r.get("findings",[])[:18],"next_steps":r.get("next_steps",[])[:10],"hypotheses":r.get("hypotheses",[])[:12],"agent_runs":r.get("agent_runs",[])[:20],"transformations":r.get("transformations",[])[:35],"verifyloop":r.get("verifyloop",{}),"agent_files":r.get("agent_files",[])[:20],"structured_clues":r.get("structured_clues",[])[:12],"chain_results":r.get("chain_results",[])[:30],"intermediate_files":r.get("intermediate_files",[])[:20],"previews":[{"name":p.get("name"),"score":p.get("score"),"ocr":p.get("ocr","")[:600],"qr":p.get("qr","")[:600]} for p in r.get("previews",[])[:18]],"outputs":[{"tool":o.get("tool"),"ok":o.get("ok"),"out":(o.get("out") or "")[:1800]} for o in r.get("outputs",[])[:16]]})
    return "Local CTF project only. Target flag format ctf_cs{...}. Prioritize exact flags, braces, chain results, generated intermediate files, and next steps. Give exact UI/tool actions and proof.\nProject:\n"+json.dumps(meta,ensure_ascii=False,indent=2)[:6000]+"\nArtifacts:\n"+json.dumps(compact,ensure_ascii=False,indent=2)[:60000]
def analyze_project(pid):
    root=pdir(pid); meta=jread(meta_path(pid),{})
    progress(pid,1,"Preparing project")
    for p in list(all_files(root)):
        try:
            fo=run(["file",str(p)],20).get("out","") if exists("file") else ""
            if detect_kind(p,fo)=="archive": extract_archive(p,root/"files")
        except Exception as e: log(pid,f"extract error {p.name}: {e}")
    reports=[]; analyzed=set()
    for pass_no in range(4):
        files=[p for p in all_files(root) if str(p) not in analyzed]
        if not files: break
        log(pid,f"VerifyLoop pass {pass_no+1}: {len(files)} files")
        total=max(1,len(files))
        for i,p in enumerate(files,1):
            analyzed.add(str(p))
            try: reports.append(analyze_file(pid,p,root,i,total))
            except Exception as e:
                reports.append({"id":uuid.uuid4().hex[:10],"name":p.name,"path":str(p),"rel":str(p.relative_to(root)),"kind":"error","error":str(e),"flags":[],"strings":[],"outputs":[],"previews":[],"commands":[],"decoders":[],"chain_results":[],"intermediate_files":[],"findings":[{"score":20,"type":"analysis_error","value":str(e),"why":"File pipeline failed."}],"next_steps":[{"priority":20,"step":"Inspect manually; file pipeline failed.","why":str(e)}]})
            jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    progress(pid,98,"Ranking evidence")
    jwrite(report_path(pid),{"project":meta,"files":reports,"summary":project_summary(reports,meta),"ai_prompt":ai_prompt(meta,reports),"updated":now()})
    progress(pid,100,"Done")
    with LOCK: JOBS.setdefault(pid,{})["status"]="done"
TOOL_COMMANDS={
"strings_utf16":lambda p:["bash","-lc",f"strings -el {str(p)!r} | head -1000"],
"find_files_nearby":lambda p:["bash","-lc",f"find {str(p.parent)!r} -maxdepth 3 -type f -printf '%p %s bytes\\n' | head -500"],
"grep_crypto_clues":lambda p:["bash","-lc",f"strings -a {str(p)!r} | grep -Ein 'rsa|aes|xor|base64|base32|md5|sha1|sha256|jwt|nonce|iv|key|secret|n=|e=|c=' | head -500"],
"grep_urls_tokens":lambda p:["bash","-lc",f"strings -a {str(p)!r} | grep -Eio 'https?://[^ ]+|eyJ[A-Za-z0-9_=.-]+|[A-Fa-f0-9]{{32,64}}' | head -500"],
"png_chunks":lambda p:["bash","-lc",f"xxd -g 1 {str(p)!r} | grep -aE 'IHDR|IDAT|IEND|tEXt|zTXt|iTXt|PLTE' | head -300"],
"file":lambda p:["file",str(p)],
"magic_bytes":lambda p:["bash","-lc",f"xxd -l 128 {str(p)!r}; echo; file {str(p)!r}"],
"strings":lambda p:["strings","-a",str(p)],
"strings_braces":lambda p:["bash","-lc",f"strings -a {str(p)!r} | grep -Ein 'ctf_cs|flag|\\{{|\\}}' | head -500"],
"extract_ascii_context":lambda p:["bash","-lc",f"strings -a {str(p)!r} | grep -Ein -C 3 'ctf_cs|flag|\\{{|\\}}|key|secret|raktas|slapta|token|password' | head -900"],
"rg_project":lambda p:["rg","-a","-n","ctf_cs|flag|\\{|\\}|raktas|slapta|key|secret",str(p.parent)],
"xxd_head":lambda p:["xxd","-l","20000",str(p)],
"xxd_tail":lambda p:["bash","-lc",f"tail -c 12000 {str(p)!r} | xxd"],
"sha256sum":lambda p:["sha256sum",str(p)],
"md5sum":lambda p:["md5sum",str(p)],
"exiftool":lambda p:["exiftool",str(p)],
"binwalk":lambda p:["binwalk",str(p)],
"binwalk_extract":lambda p:["binwalk","-e",str(p)],
"binwalk_recursive":lambda p:["binwalk","-Me",str(p)],
"foremost":lambda p:["foremost","-i",str(p),"-o",str(p.parent/"foremost_manual")],
"yara_basic":lambda p:["yara","-w",str(BASE/"data/basic.yar"),str(p)],
"identify":lambda p:["identify","-verbose",str(p)],
"image_magick_info":lambda p:["identify","-verbose",str(p)],
"pngcheck":lambda p:["pngcheck","-v",str(p)],
"zsteg_all":lambda p:["zsteg","-a",str(p)],
"stegseek":lambda p:["stegseek",str(p),"/usr/share/wordlists/rockyou.txt"],
"steghide_info":lambda p:["steghide","info",str(p)],
"steghide_extract_empty":lambda p:["steghide","extract","-sf",str(p),"-p","","-xf",str(p.parent/(p.name+".steghide.out"))],
"tesseract":lambda p:["tesseract",str(p),"stdout"],
"zbarimg":lambda p:["zbarimg",str(p)],
"capinfos":lambda p:["capinfos",str(p)],
"tshark_protocols":lambda p:["tshark","-r",str(p),"-q","-z","io,phs"],
"tshark_http":lambda p:["tshark","-r",str(p),"-Y","http","-T","fields","-e","frame.number","-e","http.request.full_uri","-e","http.file_data"],
"tshark_dns":lambda p:["tshark","-r",str(p),"-Y","dns","-T","fields","-e","dns.qry.name","-e","dns.txt"],
"tshark_tcp0":lambda p:["tshark","-r",str(p),"-q","-z","follow,tcp,ascii,0"],
"tshark_tcp1":lambda p:["tshark","-r",str(p),"-q","-z","follow,tcp,ascii,1"],
"tshark_tcp2":lambda p:["tshark","-r",str(p),"-q","-z","follow,tcp,ascii,2"],
"tshark_files":lambda p:["bash","-lc",f"mkdir -p {str(p.parent/'tshark_export')!r}; tshark -r {str(p)!r} --export-objects http,{str(p.parent/'tshark_export')!r}"],
"pdfinfo":lambda p:["pdfinfo",str(p)],
"pdftotext":lambda p:["pdftotext",str(p),"-"],
"pdfimages":lambda p:["pdfimages","-list",str(p)],
"pdfdetach_list":lambda p:["pdfdetach","-list",str(p)],
"pdfdetach_extract":lambda p:["bash","-lc",f"mkdir -p {str(p.parent/(p.stem+'_pdfattach'))!r}; pdfdetach -saveall -o {str(p.parent/(p.stem+'_pdfattach'))!r} {str(p)!r}"],
"qpdf_check":lambda p:["qpdf","--check",str(p)],
"seven_list":lambda p:["7z","l",str(p)],
"zipinfo":lambda p:["zipinfo",str(p)],
"zip_comment":lambda p:["zipinfo","-z",str(p)],
"hashid_file":lambda p:["bash","-lc",f"strings -a {str(p)!r} | head -500 | hashid -m 2>/dev/null"],
"readelf":lambda p:["readelf","-a",str(p)],
"elf_sections":lambda p:["readelf","-S",str(p)],
"elf_imports":lambda p:["bash","-lc",f"readelf -Ws {str(p)!r} | grep -Ei 'strcmp|memcmp|puts|printf|scanf|read|open|crypt|xor|flag|key|secret|decode' | head -400"],
"checksec_basic":lambda p:["bash","-lc",f"readelf -h {str(p)!r}; echo; readelf -l {str(p)!r} | grep -Ei 'GNU_STACK|RELRO|LOAD'"],
"objdump":lambda p:["objdump","-d",str(p)],
"objdump_rodata":lambda p:["bash","-lc",f"objdump -s -j .rodata {str(p)!r} 2>/dev/null | head -900"],
"nm":lambda p:["nm","-an",str(p)],
"r2_info":lambda p:["r2","-q","-c","iI; izz; aaa; afl; pdf @ main",str(p)],
"rabin2_info":lambda p:["rabin2","-I",str(p)],
"rabin2_strings":lambda p:["rabin2","-zz",str(p)],
"upx_test":lambda p:["upx","-t",str(p)],
"upx_decompress":lambda p:["upx","-d",str(p),"-o",str(p.parent/(p.name+".unpacked"))],
"ltrace_short":lambda p:["timeout","8","ltrace","-f",str(p)],
"strace_short":lambda p:["timeout","8","strace","-f",str(p)],
"ffprobe":lambda p:["ffprobe",str(p)],
"soxi":lambda p:["soxi",str(p)],
"spectrogram":lambda p:["ffmpeg","-y","-i",str(p),"-lavfi","showspectrumpic=s=1600x900",str(p.parent/(p.stem+"_spectrogram.png"))],
"sqlite_tables":lambda p:["sqlite3",str(p),".tables"],
"sqlite_schema":lambda p:["sqlite3",str(p),".schema"],
"python_pyc_decompile":lambda p:["uncompyle6",str(p)],
"decompyle3":lambda p:["decompyle3",str(p)],
"apktool_decode":lambda p:["apktool","d","-f",str(p),"-o",str(p.parent/(p.stem+"_apktool"))],
"jadx_decompile":lambda p:["jadx","-d",str(p.parent/(p.stem+"_jadx")),str(p)],
}
TOOL_DEPS={
"strings_utf16":["strings"],"find_files_nearby":["find"],"grep_crypto_clues":["strings","grep"],"grep_urls_tokens":["strings","grep"],"png_chunks":["xxd","grep"],
"strings_braces":["strings","grep"],"extract_ascii_context":["strings","grep"],"rg_project":["rg"],"magic_bytes":["xxd","file"],"xxd_tail":["xxd"],"binwalk_extract":["binwalk"],"binwalk_recursive":["binwalk"],"zsteg_all":["zsteg"],"stegseek":["stegseek"],"steghide_info":["steghide"],"steghide_extract_empty":["steghide"],"tshark_files":["tshark"],"pdfdetach_list":["pdfdetach"],"pdfdetach_extract":["pdfdetach"],"r2_info":["r2"],"rabin2_info":["rabin2"],"rabin2_strings":["rabin2"],"upx_test":["upx"],"upx_decompress":["upx"],"python_pyc_decompile":["uncompyle6"],"decompyle3":["decompyle3"],"apktool_decode":["apktool"],"jadx_decompile":["jadx"],"spectrogram":["ffmpeg"]
}
TOOL_SUITES={
"image":["file","magic_bytes","exiftool","identify","pngcheck","png_chunks","strings_braces","extract_ascii_context","zbarimg","tesseract","zsteg_all","binwalk","binwalk_extract","foremost","yara_basic"],
"pcap":["file","capinfos","tshark_protocols","tshark_http","tshark_dns","tshark_tcp0","tshark_tcp1","tshark_tcp2","tshark_files","strings_braces","foremost"],
"pdf":["file","pdfinfo","pdftotext","pdfimages","pdfdetach_list","exiftool","strings_braces","binwalk","foremost"],
"archive":["file","seven_list","zipinfo","zip_comment","strings_braces","binwalk","binwalk_extract","foremost","hashid_file"],
"binary":["file","magic_bytes","strings_braces","strings_utf16","extract_ascii_context","grep_crypto_clues","readelf","elf_sections","elf_imports","checksec_basic","rabin2_info","rabin2_strings","r2_info","upx_test","yara_basic"],
"media":["file","ffprobe","soxi","spectrogram","exiftool","strings_braces"],
"sqlite":["file","sqlite_tables","sqlite_schema","strings_braces"],
"apk":["file","strings_braces","apktool_decode","jadx_decompile"],
"python_bytecode":["file","strings_braces","python_pyc_decompile","decompyle3"],
"text":["file","strings_braces","strings_utf16","extract_ascii_context","grep_crypto_clues","grep_urls_tokens","strings","yara_basic"],
"generic":["file","magic_bytes","strings_braces","strings_utf16","extract_ascii_context","grep_crypto_clues","grep_urls_tokens","find_files_nearby","strings","exiftool","binwalk","foremost","yara_basic"]
}
DEEP_EXTRA={"image":["stegseek","steghide_info","steghide_extract_empty","binwalk_recursive"],"pcap":["tshark_files","binwalk_recursive"],"pdf":["pdfdetach_extract","binwalk_recursive"],"archive":["binwalk_recursive"],"binary":["objdump","objdump_rodata","nm","upx_decompress"],"generic":["rg_project","xxd_head","xxd_tail"]}
def deps_for(name,cmd=None):
    if name in TOOL_DEPS: return TOOL_DEPS[name]
    if cmd and cmd[0] not in ["bash","sh","timeout"]: return [cmd[0]]
    if cmd and cmd[0]=="timeout" and len(cmd)>2: return ["timeout",cmd[2]]
    return []
def missing_deps(name,cmd=None):
    return [d for d in deps_for(name,cmd) if not exists(d)]
def run_tool_local(path,toolname,timeout=180):
    p=Path(path)
    if not p.exists(): return {"tool":toolname,"ok":False,"cmd":"","out":"file not found","missing":[],"install_hint":""}
    if toolname not in TOOL_COMMANDS: return {"tool":toolname,"ok":False,"cmd":"","out":"unknown tool","missing":[],"install_hint":""}
    try: cmd=TOOL_COMMANDS[toolname](p)
    except Exception as e: return {"tool":toolname,"ok":False,"cmd":"","out":"command build failed: "+str(e),"missing":[],"install_hint":""}
    miss=missing_deps(toolname,cmd)
    if miss:
        hint="Missing dependencies: "+", ".join(miss)+". Run bash FULL_INSTALL.sh."
        return {"tool":toolname,"ok":False,"cmd":" ".join(map(str,cmd)),"out":hint,"missing":miss,"install_hint":hint,"evidence":[],"decoders":[]}
    res=run(cmd,timeout); res["tool"]=toolname; res["missing"]=[]; res["install_hint"]=""
    text=res.get("out","")
    res["evidence"]=extract_flagish_text(text)[:60]
    res["decoders"]=decode_candidates(text,b"")[:50]
    return res
def suite_for_path(path,suite="quick"):
    p=Path(path); fo=run(["file",str(p)],20).get("out","") if exists("file") and p.exists() else ""; k=detect_kind(p,fo) if p.exists() else "generic"
    tools=list(TOOL_SUITES.get(k,TOOL_SUITES["generic"]))
    if suite in ["deep","all"]: tools += DEEP_EXTRA.get(k,[])+DEEP_EXTRA.get("generic",[])
    out=[]; seen=set()
    for t in tools:
        if t in TOOL_COMMANDS and t not in seen: out.append(t); seen.add(t)
    return k,out
def summarize_suite(results):
    text="\n".join((r.get("out") or "")[:10000] for r in results)
    ev=extract_flagish_text(text)[:100]; dec=decode_candidates(text,b"")[:100]
    flags=[]
    for e in ev:
        if "ctf_cs{" in e.get("value","").lower() and e["value"] not in flags: flags.append(e["value"])
    for d in dec:
        for f in d.get("flags",[]) or []:
            if f not in flags: flags.append(f)
    return {"evidence":ev,"decoders":dec,"flags":flags[:80]}
FALSE_FLAG_WORDS = [
    "example","sample","test","testing","smoke","dummy","fake","placeholder","your_flag",
    "flag_here","not_the_flag","notflag","nope","wrong","todo","change_me","insert",
    "project_smoke","tool_ok","smoke_ok"
]
FORMAT_CONTEXT_WORDS = ["format","example","should look","looks like","target flag","flag format","always answer","answer format","template"]
def score_text(s):
    if not s: return 0
    s=str(s)
    if len(s)>18000: s=s[:18000]
    low=s.lower(); score=0
    if "ctf_cs{" in low: score += 240
    if "ctf_cs" in low: score += 150
    if "{" in s and "}" in s: score += 65
    elif "{" in s or "}" in s: score += 25
    for k in ["flag{","ctf{","slapta","raktas","password","key","secret","veliava","token","hidden","decode","cipher","xor","base64","admin","login","answer","winner"]:
        if k in low: score += 24
    sample=s[:12000]
    printable=sum(1 for c in sample if c.isprintable() or c in "\n\r\t")/max(1,len(sample))
    letters=sum(1 for c in sample if c.isalpha())/max(1,len(sample))
    score += min(25,int(printable*25))+min(12,int(letters*12))
    return score
def fast_flag_matches(text, limit=20, scan_limit=9000):
    text=str(text or "")[:scan_limit]
    if "{" not in text or "}" not in text: return []
    low=text.lower(); hits=[]; seen=set()
    for pref in ["ctf_cs","flag","ctf","cyber","sprint"]:
        needle=pref+"{"; start=0
        while len(hits)<limit:
            i=low.find(needle,start)
            if i<0: break
            j=text.find("}",i+len(needle))
            if j<0 or j-i>260:
                start=i+len(needle); continue
            cand=text[i:j+1]
            if cand not in seen and "\n" not in cand and "\r" not in cand:
                seen.add(cand); hits.append(cand)
            start=i+len(needle)
    return hits[:limit]
def extract_flagish_text(text):
    text=str(text or "")[:20000]
    hits=[]; seen=set()
    def add(kind,val,score,why):
        val=str(val)[:900]
        if not val: return
        k=(kind,val)
        if k in seen: return
        seen.add(k); hits.append({"type":kind,"value":val,"score":int(score),"why":why})
    for m in fast_flag_matches(text, limit=60, scan_limit=20000):
        if m.lower().startswith("ctf_cs{"):
            add("exact_ctf_cs",m,300,"Exact target-format candidate.")
        else:
            add("brace_or_flag_fragment",m,120,"Brace/flag-like fragment.")
    low=text.lower(); start=0
    while True:
        i=low.find("ctf_cs{",start)
        if i<0: break
        j=text.find("}",i)
        chunk=text[i:(j+1 if j>i and j-i<260 else min(len(text),i+260))]
        add("partial_ctf_cs",chunk,175,"Partial or full ctf_cs fragment.")
        start=i+7
        if len(hits)>80: break
    for line in text.splitlines()[:1200]:
        ll=line.lower()
        if any(x in ll for x in ["ctf_cs","flag","raktas","slapta","key","secret","token"]) or ("{" in line and "}" in line):
            if len(line)<=900: add("context_line",line,score_text(line),"Useful context line.")
        if len(hits)>=120: break
    return sorted(hits,key=lambda x:x.get("score",0),reverse=True)[:140]
def decode_candidates(text, data=b""):
    outs=[]; seen=set(); text=str(text or "")[:24000]
    def add(t,i,o,base=0):
        if not o: return
        o=str(o)[:9000]
        key=(t,o[:240])
        if key in seen: return
        seen.add(key)
        flags=fast_flag_matches(o, limit=6, scan_limit=9000)
        sc=int(base)+score_text(o)+(100 if flags else 0)
        if sc>=22 or flags:
            outs.append({"type":t,"input":str(i)[:260],"output":o,"flags":flags,"score":sc})
    chunks=re.findall(r"[A-Za-z0-9+/=_-]{8,}|[A-Z2-7=]{8,}|[0-9a-fA-F]{8,}|(?:[01]{8}\s*){2,}|(?:[0-7]{2,3}\s+){2,}[0-7]{2,3}|(?:\d{2,3}[,\s]+){3,}\d{2,3}|(?:[.\-]{1,6}\s+){3,}[.\-]{1,6}",text)[:350]
    for raw in chunks:
        s=raw.strip()
        if len(s)>2000: continue
        try:
            if len(s)<=900 and re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}",s):
                padded=s+"="*((4-len(s)%4)%4)
                add("base64",s,base64.b64decode(padded,validate=False).decode("utf-8","replace"),10)
                if "-" in s or "_" in s: add("base64_urlsafe",s,base64.urlsafe_b64decode(padded).decode("utf-8","replace"),12)
        except Exception: pass
        try:
            if len(s)<=900 and re.fullmatch(r"[A-Z2-7=]{8,}",s): add("base32",s,base64.b32decode(s).decode("utf-8","replace"),8)
        except Exception: pass
        try:
            if len(s)<=180 and re.fullmatch(r"[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{10,}",s):
                b58=try_base58(s)
                if b58 and score_text(b58)>18: add("base58",s,b58,12)
        except Exception: pass
        try:
            h=re.sub(r"\s+","",s)
            if len(h)<=2000 and len(h)%2==0 and re.fullmatch(r"[0-9a-fA-F]{8,}",h):
                add("hex",s,bytes.fromhex(h).decode("utf-8","replace"),10)
        except Exception: pass
        try:
            bits=re.sub(r"\s+","",s)
            if len(bits)<=2048 and len(bits)%8==0 and re.fullmatch(r"[01]{16,}",bits):
                add("binary",s,bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8)).decode("utf-8","replace"),10)
        except Exception: pass
        try:
            parts=s.split()
            if len(parts)>2 and len(parts)<=300 and all(re.fullmatch(r"[0-7]{2,3}",x) for x in parts):
                vals=[int(x,8) for x in parts]
                if all(0 <= v <= 255 for v in vals):
                    add("octal",s,bytes(vals).decode("utf-8","replace"),10)
        except Exception: pass
        try:
            ac=try_ascii_codes(s)
            if ac and score_text(ac)>18: add("ascii_codes",s,ac,14)
        except Exception: pass
        try:
            md=morse_decode(s)
            if md: add("morse",s,md,10)
        except Exception: pass
    visible=text[:9000]
    add("url_decode","visible",urllib.parse.unquote(visible),8)
    add("html_unescape","visible",html.unescape(visible),8)
    if len(visible)<=5000:
        add("atbash","visible",atbash(visible),8)
        add("reverse_text","visible",visible[::-1],8)
    bacon=try_bacon(visible)
    if bacon and score_text(bacon)>18: add("bacon_ab","visible",bacon,15)
    if len(visible)<=2500:
        a="abcdefghijklmnopqrstuvwxyz"; A=a.upper()
        for r in range(1,26):
            add(f"rot{r}","visible",visible.translate(str.maketrans(a+A,a[r:]+a[:r]+A[r:]+A[:r])),6)
    for hit in extract_flagish_text(visible): add(hit["type"],"flag/brace hunter",hit["value"],hit["score"])
    for ctx in expert_context_lines(visible)[:40]: add("context_near_flag_or_brace","context hunter",ctx,18)
    if data:
        outs+=xor_single(data)[:12]+repeating_xor_guesses(data)[:10]+try_decompress_bytes(data)[:8]+xor_crib_ctf_cs(data)[:8]
    return sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:260]
def recursive_decode_seed(text,max_rounds=2):
    text=str(text or "")[:9000]
    results=[]; seen=set(); frontier=[("input",text)]
    for depth in range(max_rounds):
        new=[]
        for label,val in frontier[:12]:
            key=(label,val[:220])
            if key in seen: continue
            seen.add(key)
            for item in decode_candidates(val,b"")[:14]:
                out=(item.get("output","") or "")[:9000]
                item=dict(item); item["output"]=out; item["type"]=f"{label}->{item['type']}"; item["score"]=item.get("score",0)+depth*8
                results.append(item)
                if out and score_text(out)>45 and len(new)<10: new.append((item["type"],out))
        frontier=new[:10]
    return sorted(results,key=lambda x:x.get("score",0),reverse=True)[:80]
def seed_texts(report):
    seeds=[]
    def add(source,text,weight=0,limit=9000):
        text=str(text or "")
        if text.strip(): seeds.append({"source":source,"text":text[:limit],"weight":weight})
    add("file_type",report.get("file",""),5,2000)
    add("strings","\n".join(report.get("strings",[])[:1000]),20,9000)
    for o in report.get("outputs",[])[:80]:
        name=str(o.get("tool","")); txt=o.get("out","") or ""
        if "not installed" in txt.lower(): continue
        limit=4500 if any(x in name.lower() for x in ["strings","xxd","objdump","readelf"]) else 7000
        add("tool:"+name,txt,15,limit)
    for p in report.get("previews",[])[:40]:
        add("preview:"+str(p.get("name","")), (p.get("qr","") or "")+"\n"+(p.get("ocr","") or ""),30+int(p.get("score",0)),5000)
    for ctx in report.get("expert_contexts",[])[:80]: add("context",ctx,40,2000)
    out=[]; seen=set()
    for s in sorted(seeds,key=lambda x:x.get("weight",0),reverse=True):
        k=(s["source"],s["text"][:220])
        if k not in seen: seen.add(k); out.append(s)
    return out[:70]
def chain_decode_report(report,raw=b""):
    chain=[]
    for seed in seed_texts(report)[:55]:
        for item in decode_candidates(seed["text"], raw if seed["source"]=="strings" else b"")[:18]:
            item=dict(item); item["chain_source"]=seed["source"]; item["score"]=item.get("score",0)+seed.get("weight",0); chain.append(item)
        if seed.get("weight",0)>=35 and len(seed.get("text",""))<=3500 and any(x in seed.get("text","").lower() for x in ["ctf","flag","base","xor","rsa","{","}"]):
            for item in recursive_decode_seed(seed["text"])[:8]:
                item=dict(item); item["chain_source"]=seed["source"]+" -> recursive"; item["score"]=item.get("score",0)+seed.get("weight",0)+10; chain.append(item)
    if raw: chain += try_decompress_bytes(raw)[:6]+xor_crib_ctf_cs(raw)[:6]
    out=[]; seen=set()
    for c in sorted(chain,key=lambda x:x.get("score",0),reverse=True):
        k=(c.get("type"),(c.get("output","") or "")[:220])
        if k not in seen: seen.add(k); out.append(c)
    return out[:160]
def internal_tool_result(path, toolname):
    p=Path(path)
    try: data=readbytes(p,4_000_000)
    except Exception as e: return {"tool":toolname,"ok":False,"cmd":"internal:"+toolname,"out":"read failed: "+str(e),"missing":[],"install_hint":"","evidence":[],"decoders":[]}
    strings_list=py_strings(data, limit=3000); text="\n".join(strings_list); out=""
    if toolname=="magic_bytes": out="Magic/head bytes:\n"+data[:160].hex(" ")+"\n\nASCII preview:\n"+data[:800].decode("utf-8","replace")
    elif toolname=="strings": out=text
    elif toolname=="strings_braces":
        lines=[s for s in strings_list if any(k in s.lower() for k in ["ctf_cs","flag","raktas","slapta"]) or "{" in s or "}" in s]
        out="\n".join(f"{i+1}:{line}" for i,line in enumerate(lines[:500]))
    elif toolname=="extract_ascii_context":
        lines=[]
        for i,s in enumerate(strings_list):
            low=s.lower()
            if any(k in low for k in ["ctf_cs","flag","raktas","slapta","key","secret","token","password"]) or "{" in s or "}" in s:
                lines.append("\n".join(strings_list[max(0,i-2):min(len(strings_list),i+3)]))
        out="\n---\n".join(lines[:120])
    elif toolname=="grep_crypto_clues":
        pat=re.compile(r"rsa|aes|xor|base64|base32|base58|md5|sha1|sha256|jwt|nonce|iv|key|secret|n=|e=|c=|p=|q=",re.I)
        out="\n".join(s for s in strings_list if pat.search(s))[:50000]
    elif toolname=="grep_urls_tokens":
        matches=[]
        for s in strings_list:
            matches += re.findall(r"https?://[^\s'\"<>]+|eyJ[A-Za-z0-9_=.-]+|[A-Fa-f0-9]{32,64}",s)
            if len(matches)>500: break
        out="\n".join(matches[:500])
    elif toolname=="strings_utf16":
        try: out="\n".join(re.findall(r"[ -~]{4,}", data.decode("utf-16le","ignore"))[:1200])
        except Exception: out=""
    elif toolname=="hashid_file":
        vals=[]
        for s in strings_list:
            for h in re.findall(r"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b",s):
                vals.append(f"{h} :: "+{32:"possible MD5/NTLM",40:"possible SHA1",64:"possible SHA256"}[len(h)])
        out="\n".join(vals[:500])
    elif toolname=="sha256sum": out=hashlib.sha256(data).hexdigest()+"  "+str(p)
    elif toolname=="md5sum": out=hashlib.md5(data).hexdigest()+"  "+str(p)
    else: return None
    res={"tool":toolname,"ok":True,"cmd":"internal:"+toolname,"out":out[:120000],"missing":[],"install_hint":""}
    res["evidence"]=extract_flagish_text(res["out"])[:60]
    res["decoders"]=decode_candidates(res["out"],b"")[:50]
    return res
def run_tool_local(path,toolname,timeout=180):
    p=Path(path)
    if not p.exists(): return {"tool":toolname,"ok":False,"cmd":"","out":"file not found","missing":[],"install_hint":""}
    internal=internal_tool_result(p,toolname)
    if internal is not None: return internal
    if toolname not in TOOL_COMMANDS: return {"tool":toolname,"ok":False,"cmd":"","out":"unknown tool","missing":[],"install_hint":""}
    try: cmd=TOOL_COMMANDS[toolname](p)
    except Exception as e: return {"tool":toolname,"ok":False,"cmd":"","out":"command build failed: "+str(e),"missing":[],"install_hint":""}
    miss=missing_deps(toolname,cmd)
    if miss:
        hint="Missing dependencies: "+", ".join(miss)+". Run bash FULL_INSTALL.sh."
        return {"tool":toolname,"ok":False,"cmd":" ".join(map(str,cmd)),"out":hint,"missing":miss,"install_hint":hint,"evidence":[],"decoders":[]}
    res=run(cmd,timeout); res["tool"]=toolname; res["missing"]=[]; res["install_hint"]=""
    text=res.get("out","")
    res["evidence"]=extract_flagish_text(text)[:60]
    res["decoders"]=decode_candidates(text,b"")[:50]
    return res
def verifyloop_relevant_tools(path, kind):
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
    tools=by_kind.get(kind,by_kind["generic"]); out=[]; seen=set()
    for t in tools:
        if t in TOOL_COMMANDS and t not in seen: seen.add(t); out.append(t)
    return out[:45]
def verifyloop_run_tools(pid,path,report,root):
    kind=report.get("kind","generic"); tools=verifyloop_relevant_tools(path,kind); results=[]
    log(pid,f"VerifyLoop: {path.name} kind={kind} auto-tools={len(tools)}")
    slow={"binwalk_extract","foremost","tshark_files","pdfdetach_extract","pdfimages","apktool_decode","jadx_decompile","spectrogram","r2_info","zsteg_all","stegseek"}
    for tool in tools:
        try:
            r=run_tool_local(path,tool,35 if tool in slow else 4)
            r["auto"]=True; r["tool"]="verifyloop:"+tool; results.append(r)
            report.setdefault("commands",[]).append(r.get("cmd",""))
            for ev in r.get("evidence",[]) or []:
                val=ev.get("value","")
                if "ctf_cs{" in val.lower() and val not in report.setdefault("flags",[]): report["flags"].append(val)
            for d in r.get("decoders",[]) or []:
                for f in d.get("flags",[]) or []:
                    if f not in report.setdefault("flags",[]): report["flags"].append(f)
        except Exception as e:
            results.append({"tool":"verifyloop:"+tool,"ok":False,"cmd":tool,"out":"VerifyLoop tool failed: "+str(e),"auto":True})
    added=verifyloop_add_outputs(report,results)
    return {"tools":tools,"added_outputs":len(added),"results":results}
def verifyloop_refresh_analysis(report, raw_data):
    outtxt="\n".join((o.get("out") or "")[:6000] for o in report.get("outputs",[])[:120])
    combined="\n".join(report.get("strings",[])[:1200])+"\n"+outtxt
    report["expert_contexts"]=expert_context_lines(combined)[:100]
    report["decoders"]=sorted(decode_candidates(combined,raw_data)+recursive_decode_seed(combined),key=lambda x:x.get("score",0),reverse=True)[:300]
    report["chain_results"]=chain_decode_report(report,raw_data)
    report["structured_clues"]=detect_structured_clues(combined[:30000]+"\n"+"\n".join((c.get("output","") or "")[:2000] for c in report.get("chain_results",[])[:40]))
    report["hypotheses"]=classify_workflow_hypotheses(report)
    return report
def normalize_flag_candidate(flag):
    flag=str(flag or "").strip()
    m=CTF_CS_RE.search(flag)
    if m: return m.group(0)
    hits=fast_flag_matches(flag,limit=1,scan_limit=400)
    return hits[0] if hits else flag[:300]
def flag_inner(flag):
    m=re.search(r"\{(.*)\}",flag)
    return m.group(1) if m else ""
def is_flag_placeholder(flag,context="",source=""):
    low=(flag+"\n"+context+"\n"+source).lower(); inner=flag_inner(flag).lower(); reasons=[]
    if flag.lower() in ["ctf_cs{...}","ctf_cs{}","ctf_cs{flag}","ctf_cs{your_flag}","ctf_cs{flag_here}"]:
        reasons.append("looks like format/template, not a solved flag")
    if any(w in inner for w in FALSE_FLAG_WORDS): reasons.append("contains placeholder/test/fake wording")
    if any(w in low for w in FORMAT_CONTEXT_WORDS) and ("ctf_cs{...}" in low or "flag format" in low): reasons.append("near format/example wording")
    if len(inner)<3: reasons.append("flag body too short")
    if len(inner)>180: reasons.append("flag body too long")
    if re.fullmatch(r"[.]+",inner or ""): reasons.append("flag body is only dots")
    return reasons
def source_weight(source):
    s=str(source).lower()
    if "raw_bytes" in s or "original_strings" in s: return 85
    if "decoder" in s or "chain" in s: return 75
    if "transform" in s or "transformation_file_scan" in s: return 70
    if "ocr" in s or "qr" in s or "preview" in s: return 68
    if "tool:" in s or "verifyloop:" in s: return 58
    if "agent" in s: return 32
    return 40
def add_flag_source(bucket,flag,source,context="",base=0):
    flag=normalize_flag_candidate(flag)
    if not flag or "{" not in flag or "}" not in flag: return
    key=flag.lower()
    item=bucket.setdefault(key,{"flag":flag,"sources":[],"contexts":[],"score":0,"reasons":[],"negative_reasons":[]})
    item["sources"].append(str(source)[:240])
    if context: item["contexts"].append(str(context)[:900])
    item["score"]+=source_weight(source)+int(base)
    if flag.lower().startswith("ctf_cs{"): item["score"]+=70; item["reasons"].append("matches target ctf_cs{...} format")
    else: item["score"]+=20; item["reasons"].append("flag-like braces but not exact target prefix")
    inner=flag_inner(flag)
    if 6<=len(inner)<=80: item["score"]+=18; item["reasons"].append("reasonable flag body length")
    if re.fullmatch(r"[A-Za-z0-9_!@#$%^&*+\-=:;,.?/|]+",inner or ""): item["score"]+=10; item["reasons"].append("flag body charset looks plausible")
    if any(w in (context or "").lower() for w in ["decoded","decrypted","success","found","output","hidden","secret","raktas","slapta"]):
        item["score"]+=20; item["reasons"].append("supportive solve-context words nearby")
    neg=is_flag_placeholder(flag,context,source)
    if neg: item["negative_reasons"].extend(neg); item["score"]-=120+35*len(neg)
def collect_verified_flags(report):
    bucket={}
    for f in report.get("flags",[])[:80]: add_flag_source(bucket,f,"raw_bytes/original_strings","direct candidate from raw file or previous pipeline",25)
    for s in report.get("strings",[])[:600]:
        for f in fast_flag_matches(s,limit=5,scan_limit=1200): add_flag_source(bucket,f,"original_strings",s[:900],30)
    for o in report.get("outputs",[])[:120]:
        txt=o.get("out","") or ""
        if "not installed" in txt.lower(): continue
        src="tool:"+str(o.get("tool",""))
        for f in fast_flag_matches(txt,limit=15,scan_limit=12000):
            idx=txt.lower().find(f.lower()); ctx=txt[max(0,idx-260):idx+len(f)+260] if idx>=0 else txt[:700]
            add_flag_source(bucket,f,src,ctx,15)
    for d in report.get("decoders",[])[:160]:
        txt=(d.get("output","") or "")[:9000]; src="decoder:"+str(d.get("type",""))
        vals=list(d.get("flags",[]) or [])[:8]+fast_flag_matches(txt,limit=8,scan_limit=9000)
        for f in vals[:12]: add_flag_source(bucket,f,src,txt[:900],int(d.get("score",0)//8))
    for c in report.get("chain_results",[])[:160]:
        txt=(c.get("output","") or "")[:9000]; src="chain:"+str(c.get("type",""))+" from "+str(c.get("chain_source",""))
        vals=list(c.get("flags",[]) or [])[:8]+fast_flag_matches(txt,limit=8,scan_limit=9000)
        for f in vals[:12]: add_flag_source(bucket,f,src,txt[:900],int(c.get("score",0)//7))
    for p in report.get("previews",[])[:40]:
        txt=((p.get("qr","") or "")+"\n"+(p.get("ocr","") or ""))[:9000]; src="preview_ocr_qr:"+str(p.get("name",""))
        vals=list(p.get("flags",[]) or [])[:8]+fast_flag_matches(txt,limit=8,scan_limit=9000)
        for f in vals[:12]: add_flag_source(bucket,f,src,txt[:900],int(p.get("score",0)//6))
    for t in (report.get("transformations",[])+report.get("intermediate_files",[])+report.get("agent_files",[]))[:100]:
        p=Path(t.get("path","")); txt=""
        try:
            if p.exists() and p.is_file() and p.stat().st_size<=700_000:
                if p.suffix.lower() in [".txt",".json",".log",".csv",".xml",".html",".md"] or any(x in p.name.lower() for x in ["decoded","strings","stream","dns","jwt","rsa","hash"]):
                    txt=p.read_text(encoding="utf-8",errors="ignore")[:9000]
        except Exception: txt=""
        if not txt: continue
        src="transform:"+str(t.get("kind",""))+":"+str(t.get("source",""))
        for f in fast_flag_matches(txt,limit=10,scan_limit=9000): add_flag_source(bucket,f,src,txt[:900],int(t.get("score",0)//5))
    verified=[]
    for item in bucket.values():
        item["sources"]=sorted(set(item.get("sources",[])))[:12]
        item["contexts"]=item.get("contexts",[])[:5]
        item["reasons"]=sorted(set(item.get("reasons",[])))[:8]
        item["negative_reasons"]=sorted(set(item.get("negative_reasons",[])))[:8]
        independent=len(set(s.split(":")[0] for s in item["sources"]))
        if independent>=2: item["score"]+=35; item["reasons"].append("seen through multiple evidence families")
        if item["negative_reasons"]: item["status"]="low" if item["score"]<160 else "possible"
        elif item["score"]>=260: item["status"]="confirmed"
        elif item["score"]>=185: item["status"]="likely"
        elif item["score"]>=110: item["status"]="possible"
        else: item["status"]="low"
        verified.append(item)
    return sorted(verified,key=lambda x:x.get("score",0),reverse=True)[:120]
def apply_verified_flags(report):
    verified=collect_verified_flags(report)
    report["verified_flags"]=verified
    report["flags"]=[v["flag"] for v in verified if v.get("status") in ["confirmed","likely"] and not v.get("negative_reasons")]
    return report
