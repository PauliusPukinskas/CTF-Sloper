# Auto-split from sloper_legacy_monolith.py lines 3526-...
def internal_tool_result(path, toolname):
    p=Path(path)
    try:
        data=readbytes(p, 4_000_000)
    except Exception as e:
        return {"tool":toolname,"ok":False,"cmd":"internal:"+toolname,"out":"read failed: "+str(e),"missing":[],"install_hint":"","evidence":[],"decoders":[]}
    strings_list=py_strings(data, limit=3000)
    out=None
    if toolname=="file":
        out=f"{p}: data, size={len(data)} bytes, sha256={hashlib.sha256(data).hexdigest()}"
    elif toolname=="magic_bytes":
        out="Magic/head bytes:\n"+data[:160].hex(" ")+"\n\nASCII preview:\n"+data[:1000].decode("utf-8","replace")
    elif toolname=="strings":
        out="\n".join(strings_list)
    elif toolname=="strings_braces":
        lines=[s for s in strings_list if any(k in s.lower() for k in ["ctf_cs","flag","raktas","slapta"]) or "{" in s or "}" in s]
        out="\n".join(f"{i+1}:{line}" for i,line in enumerate(lines[:500]))
    elif toolname=="extract_ascii_context":
        lines=[]
        for i,s in enumerate(strings_list):
            low=s.lower()
            if any(k in low for k in ["ctf_cs","flag","raktas","slapta","key","secret","token","password","jwt","rsa","base64"]) or "{" in s or "}" in s:
                ctx=strings_list[max(0,i-2):min(len(strings_list),i+3)]
                lines.append("\n".join(ctx))
        out="\n---\n".join(lines[:120])
    elif toolname=="grep_crypto_clues":
        pat=re.compile(r"rsa|aes|xor|base64|base32|base58|md5|sha1|sha256|jwt|nonce|iv|key|secret|n=|e=|c=|p=|q=|eyj", re.I)
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
    if out is None:
        return None
    res={"tool":toolname,"ok":True,"cmd":"internal:"+toolname,"out":out[:120000],"missing":[],"install_hint":""}
    res["evidence"]=extract_flagish_text(res["out"])[:60]
    res["decoders"]=decode_candidates(res["out"], b"")[:50]
    return stableworkbench_limit_tool_output(res) if "stableworkbench_limit_tool_output" in globals() else res
def verifyloop_relevant_tools(path, kind):
    """DeepPattern bounded auto tools. Text/crypto stays internal and fast."""
    internal_core=["file","magic_bytes","strings","strings_braces","extract_ascii_context","grep_crypto_clues","grep_urls_tokens","strings_utf16","hashid_file"]
    by_kind={
        "text": internal_core,
        "generic": internal_core + ["binwalk"],
        "image": internal_core + ["exiftool","identify","pngcheck","png_chunks","zbarimg","tesseract","zsteg_all","steghide_info","stegseek","binwalk","binwalk_extract","foremost"],
        "pcap": internal_core + ["capinfos","tshark_protocols","tshark_http","tshark_dns","tshark_tcp0","tshark_tcp1","tshark_tcp2","tshark_files"],
        "pdf": internal_core + ["pdfinfo","pdftotext","pdfimages","pdfdetach_list","pdfdetach_extract","qpdf_check"],
        "archive": internal_core + ["seven_list","zipinfo","zip_comment","binwalk","binwalk_extract","foremost"],
        "binary": internal_core + ["readelf","elf_sections","elf_imports","checksec_basic","rabin2_info","rabin2_strings","r2_info","upx_test","objdump_rodata","nm"],
        "media": internal_core + ["ffprobe","soxi","spectrogram","binwalk"],
        "sqlite": internal_core + ["sqlite_tables","sqlite_schema"],
        "apk": internal_core + ["apktool_decode","jadx_decompile"],
        "python_bytecode": internal_core + ["python_pyc_decompile","decompyle3"],
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
    log(pid,f"DeepPattern: {path.name} kind={kind} auto-tools={len(tools)}")
    slow={"binwalk_extract","foremost","tshark_files","pdfdetach_extract","pdfimages","apktool_decode","jadx_decompile","spectrogram","r2_info","zsteg_all","stegseek"}
    for tool in tools:
        try:
            timeout=25 if tool in slow else 3
            r=run_tool_local(path,tool,timeout)
            r["auto"]=True
            r["tool"]="deeppattern:"+tool
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
            results.append({"tool":"deeppattern:"+tool,"ok":False,"cmd":tool,"out":"DeepPattern tool failed: "+str(e),"auto":True})
    added=verifyloop_add_outputs(report,results) if "verifyloop_add_outputs" in globals() else []
    return {"tools":tools,"added_outputs":len(added),"results":results}
def cl_flag_set(summary):
    return sorted(set(x.get("flag","") for x in (summary or {}).get("flags",[]) if x.get("flag")))
def cl_project_health(reports, summary):
    total=len(reports)
    solved=sum(1 for r in reports if r.get("flags"))
    unresolved=[r for r in reports if not r.get("flags")]
    artifact_count=sum(len(r.get("artifacts",[])) for r in reports)
    recipe_count=sum(len(r.get("recipe_runs",[])) for r in reports)
    noisy=sum((r.get("candidate_health",{}) or {}).get("negative_or_noisy_candidates",0) for r in reports)
    return {
        "files_total": total,
        "files_solved": solved,
        "files_unresolved": len(unresolved),
        "solve_ratio": round(solved/max(1,total),3),
        "artifacts_total": artifact_count,
        "recipes_total": recipe_count,
        "hidden_noisy_candidates": noisy,
        "promoted_flags": len(summary.get("flags",[])),
        "status": "solved" if summary.get("flags") else ("needs_review" if artifact_count or recipe_count else "no_signal")
    }
def cl_unresolved_plan(reports):
    plans=[]
    for r in reports:
        if r.get("flags"):
            continue
        top_recipe=(r.get("recipe_runs") or [{}])[0]
        top_art=(r.get("artifacts") or [{}])[0]
        top_chain=(r.get("chain_results") or [{}])[0]
        reason=[]
        if r.get("verified_flags"):
            reason.append("has verified-but-not-promoted candidates")
        if r.get("artifacts"):
            reason.append("has generated artifacts")
        if r.get("chain_results"):
            reason.append("has decoder chain output")
        if not reason:
            reason.append("low signal")
        plans.append({
            "file": r.get("rel"),
            "kind": r.get("kind"),
            "why_unresolved": ", ".join(reason),
            "best_recipe": top_recipe.get("name",""),
            "best_recipe_score": top_recipe.get("score",0),
            "best_artifact": top_art.get("name",""),
            "best_artifact_path": top_art.get("path",""),
            "best_chain_type": top_chain.get("type",""),
            "best_chain_score": top_chain.get("score",0),
            "next_actions": [
                "Open this file → Artifacts",
                "Open this file → Recipes",
                "Open this file → Chain",
                "Run manual Deep Suite only if artifacts/recipes do not explain it"
            ]
        })
    return sorted(plans, key=lambda x:(x.get("best_recipe_score",0), x.get("best_chain_score",0)), reverse=True)[:120]
def cl_make_project_brief(root, reports, summary):
    outdir=root/"generated"/"challengelab"
    outdir.mkdir(parents=True, exist_ok=True)
    brief={
        "health": cl_project_health(reports, summary),
        "flags": summary.get("flags",[]),
        "unresolved": cl_unresolved_plan(reports),
        "top_recipes": summary.get("recipes",[])[:30],
        "top_artifacts": summary.get("artifacts",[])[:40],
        "top_evidence": summary.get("evidence_board",[])[:30],
        "priority_files": summary.get("priority_files",[])[:40],
    }
    p=outdir/"project_challengelab_brief.json"
    try:
        p.write_text(json.dumps(brief, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"kind":"project_brief","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"ChallengeLab","score":100,"note":"Project-level summary for human/local AI review","exists":True,"size":p.stat().st_size,"file":"project"}
    except Exception:
        return None
def project_summary(reports, meta):
    # Use previous Smart/Deep summary, then add ChallengeLab health/brief fields.
    flags=[]; verified_map={}; kinds={}; evidence=[]; chains=[]; actions=[]; missing=[]; agents=[]; transforms=[]; verifyloops=[]; artifacts=[]; recipes=[]; graphs=[]
    root_guess = None
    for r in reports:
        # Reports already got full postprocess during analyze_file; keep this light.
        try:
            smartsolve_postprocess(r, Path(r.get("path","")).parents[1] if r.get("path") else BASE)
        except Exception:
            try: stableworkbench_apply_report_postprocess(r)
            except Exception: pass
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
        workflow.append({"priority":100,"step":"Submit/check top ChallengeLab verified flag.","why":"Candidate survived strict filters and has supporting source path."})
    elif verified_all:
        workflow.append({"priority":94,"step":"Open Verified Flags and inspect candidates.","why":"Candidates exist, but none were promoted enough for automatic trust."})
    if recipes:
        workflow.append({"priority":92,"step":"Open Recipes tab and follow top recipe.","why":"Recipe Engine picked likely solve paths."})
    if artifacts:
        workflow.append({"priority":90,"step":"Open Artifacts browser.","why":"Generated/transformed/extracted files are collected with open/copy controls."})
    if evidence:
        workflow.append({"priority":88,"step":"Open Evidence Board top item.","why":"Noisy candidates are hidden."})
    if not workflow:
        workflow.append({"priority":50,"step":"Open Files → priority file → Artifacts/Tools.","why":"No strong signal yet."})
    priority=sorted([{"file":r.get("rel"),"kind":r.get("kind"),"flags":len(r.get("flags",[])),"verified":len(r.get("verified_flags_visible",[])),"recipes":len(r.get("recipe_runs",[])),"artifacts":len(r.get("artifacts",[])),"findings":len(r.get("findings",[])),"chains":len(r.get("chain_results",[])),"top_score":max([x.get("score",0) for x in r.get("findings",[])]+[0])} for r in reports],key=lambda x:(x["flags"],x["verified"],x["recipes"],x["top_score"],x["artifacts"]),reverse=True)[:120]
    base_summary={"flags":flags,"verified_flags":verified_all,"exact_flags":exact,"kinds":kinds,"evidence_board":evidence,"top_findings":evidence,"top_chains":chains,"agents":sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:160],"transformations":sorted(transforms,key=lambda x:x.get("score",0),reverse=True)[:240],"artifacts":artifacts,"recipes":recipes,"artifact_graphs":graphs[:120],"verifyloops":verifyloops[:160],"hypotheses":workflowbrain_project_hypotheses(reports) if "workflowbrain_project_hypotheses" in globals() else [],"workflow_steps":sorted(workflow+actions,key=lambda x:x.get("priority",0),reverse=True)[:160],"missing_tools":sorted(set(missing))[:100],"priority_files":priority}
    base_summary["health"]=cl_project_health(reports, base_summary)
    base_summary["unresolved_plan"]=cl_unresolved_plan(reports)
    # Add project brief artifact if possible.
    try:
        paths=[Path(r.get("path","")) for r in reports if r.get("path")]
        root=paths[0].parents[1] if paths and len(paths[0].parents)>1 else BASE
        brief=cl_make_project_brief(root, reports, base_summary)
        if brief:
            base_summary["artifacts"].insert(0, brief)
    except Exception:
        pass
    return base_summary
def cl_build_temp_project(root, name, files):
    pid="selfcheck_"+safe(name)+"_"+uuid.uuid4().hex[:6]
    pr=pdir(pid)
    (pr/"files").mkdir(parents=True, exist_ok=True)
    for rel, content, mode in files:
        dest=pr/"files"/rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if mode=="bytes":
            dest.write_bytes(content)
        else:
            dest.write_text(str(content), encoding="utf-8")
    jwrite(meta_path(pid), {"id":pid,"title":"selfcheck "+name,"statement":"","category":"selfcheck","created":now(),"file_count":len(files)})
    return pid
def cl_run_self_checks():
    """Temporary local regression checks. Creates and deletes projects; does not ship challenge samples."""
    results=[]
    temp_ids=[]
    import base64 as _b64, zipfile as _zip
    try:
        # Multi-layer.
        flag=b"ctf_cs{selfcheck_multi_layer_ok}"
        layer1=_b64.b64encode(flag).decode()
        layer2=layer1.encode().hex()
        layer3=_b64.b64encode(layer2.encode()).decode()
        pid=cl_build_temp_project(BASE,"multi_layer",[("multi.txt","format ctf_cs{...}\nblob="+layer3,"text")])
        temp_ids.append(pid); analyze_project(pid); rep=jread(report_path(pid),{})
        ok="ctf_cs{selfcheck_multi_layer_ok}" in [x.get("flag") for x in rep.get("summary",{}).get("flags",[])]
        results.append({"name":"multi_layer_base64_hex_base64","ok":ok,"flags":cl_flag_set(rep.get("summary",{}))})
        # XOR.
        plain=b"noise::ctf_cs{selfcheck_xor_crib_ok}::end"; key=b"k3y"
        enc=bytes(b ^ key[i%len(key)] for i,b in enumerate(plain))
        pid=cl_build_temp_project(BASE,"xor_crib",[("xor.bin",enc,"bytes")])
        temp_ids.append(pid); analyze_project(pid); rep=jread(report_path(pid),{})
        ok="ctf_cs{selfcheck_xor_crib_ok}" in json.dumps(rep)
        results.append({"name":"aligned_repeating_xor_crib","ok":ok,"flags":cl_flag_set(rep.get("summary",{}))})
        # JWT.
        h=_b64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        p=_b64.urlsafe_b64encode(b'{"msg":"ctf_cs{selfcheck_jwt_ok}"}').decode().rstrip("=")
        pid=cl_build_temp_project(BASE,"jwt",[("jwt.txt","token="+h+"."+p+".","text")])
        temp_ids.append(pid); analyze_project(pid); rep=jread(report_path(pid),{})
        ok="ctf_cs{selfcheck_jwt_ok}" in json.dumps(rep)
        results.append({"name":"jwt_payload_decode","ok":ok,"flags":cl_flag_set(rep.get("summary",{}))})
        # ZIP child.
        pid="selfcheck_zip_"+uuid.uuid4().hex[:6]
        pr=pdir(pid); (pr/"files").mkdir(parents=True, exist_ok=True)
        zp=pr/"files"/"nested.zip"
        with _zip.ZipFile(zp,"w") as z:
            z.writestr("readme.txt","hint "+_b64.b64encode(b"ctf_cs{selfcheck_zip_child_ok}").decode())
        jwrite(meta_path(pid), {"id":pid,"title":"selfcheck zip","statement":"","category":"selfcheck","created":now(),"file_count":1})
        temp_ids.append(pid); analyze_project(pid); rep=jread(report_path(pid),{})
        ok="ctf_cs{selfcheck_zip_child_ok}" in json.dumps(rep)
        results.append({"name":"nested_zip_child_decode","ok":ok,"flags":cl_flag_set(rep.get("summary",{}))})
        passed=sum(1 for r in results if r["ok"])
        return {"ok":passed==len(results),"passed":passed,"total":len(results),"results":results}
    finally:
        for pid in temp_ids:
            try: shutil.rmtree(pdir(pid), ignore_errors=True)
            except Exception: pass
async def self_check_endpoint():
    try:
        return cl_run_self_checks()
    except Exception as e:
        return {"ok":False,"error":str(e)}
async def self_check_get_endpoint():
    try:
        return cl_run_self_checks()
    except Exception as e:
        return {"ok":False,"error":str(e)}
def decode_candidates(text, data=b""):
    """Bounded decoder: no full ROT spam. DeepPattern handles harder ROT/stack search."""
    outs=[]; seen=set(); text=str(text or "")[:18000]
    def add(t,i,o,base=0):
        if not o: return
        o=str(o)[:9000]
        key=(t,o[:240])
        if key in seen: return
        seen.add(key)
        flags=fast_flag_matches(o, limit=6, scan_limit=9000) if "fast_flag_matches" in globals() else FLAG_TEXT_RE.findall(o[:9000])
        sc=int(base)+score_text(o)+(100 if flags else 0)
        if sc>=30 or flags:
            outs.append({"type":t,"input":str(i)[:260],"output":o,"flags":flags,"score":sc})
    chunks=[]
    # Prefer key=value payloads and exact long tokens.
    for m in re.finditer(r"\b[A-Za-z0-9_.-]{1,40}\s*[:=]\s*([A-Za-z0-9+/=_-]{8,})", text):
        chunks.append(m.group(1))
    chunks += re.findall(r"[A-Za-z0-9+/=_-]{12,}|[A-Fa-f0-9]{16,}|(?:[01]{8}\s*){2,}|(?:\d{2,3}[,\s]+){3,}\d{2,3}", text)
    chunks=chunks[:220]
    for raw in chunks:
        s=raw.strip().strip("'\"`")
        if len(s)>2500: continue
        compact=re.sub(r"\s+","",s)
        try:
            if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}",compact):
                padded=compact+"="*((4-len(compact)%4)%4)
                add("base64",s,base64.b64decode(padded,validate=False).decode("utf-8","replace"),10)
                add("base64_urlsafe",s,base64.urlsafe_b64decode(padded).decode("utf-8","replace"),12)
        except Exception: pass
        try:
            if len(compact)%2==0 and re.fullmatch(r"[0-9a-fA-F]{8,}",compact):
                add("hex",s,bytes.fromhex(compact).decode("utf-8","replace"),10)
        except Exception: pass
        try:
            if re.fullmatch(r"[A-Z2-7=]{8,}",compact):
                add("base32",s,base64.b32decode(compact+"="*((8-len(compact)%8)%8)).decode("utf-8","replace"),8)
        except Exception: pass
        try:
            ac=try_ascii_codes(s)
            if ac and score_text(ac)>25: add("ascii_codes",s,ac,12)
        except Exception: pass
    visible=text[:8000]
    try: add("url_decode","visible",urllib.parse.unquote(visible),8)
    except Exception: pass
    try: add("html_unescape","visible",html.unescape(visible),8)
    except Exception: pass
    if len(visible)<=5000:
        add("reverse_text","visible",visible[::-1],8)
    for hit in extract_flagish_text(visible)[:40]:
        add(hit["type"],"flag/brace hunter",hit["value"],hit["score"])
    for ctx in expert_context_lines(visible)[:20]:
        add("context_near_flag_or_brace","context hunter",ctx,18)
    if data:
        outs += xor_single(data)[:6] + try_decompress_bytes(data)[:5] + xor_crib_ctf_cs(data)[:5]
    return sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:180]
def recursive_decode_seed(text,max_rounds=1):
    text=str(text or "")[:6000]
    results=[]; seen=set(); frontier=[("input",text)]
    for depth in range(max_rounds):
        new=[]
        for label,val in frontier[:8]:
            key=(label,val[:220])
            if key in seen: continue
            seen.add(key)
            for item in decode_candidates(val,b"")[:10]:
                out=(item.get("output","") or "")[:6000]
                item=dict(item); item["output"]=out; item["type"]=f"{label}->{item['type']}"; item["score"]=item.get("score",0)+depth*8
                results.append(item)
                if out and score_text(out)>60 and len(new)<5:
                    new.append((item["type"],out))
        frontier=new[:5]
    return sorted(results,key=lambda x:x.get("score",0),reverse=True)[:50]
def chain_decode_report(report,raw=b""):
    chain=[]
    for seed in seed_texts(report)[:35]:
        for item in decode_candidates(seed["text"], raw if seed["source"]=="strings" else b"")[:14]:
            item=dict(item); item["chain_source"]=seed["source"]; item["score"]=item.get("score",0)+seed.get("weight",0); chain.append(item)
        if seed.get("weight",0)>=45 and len(seed.get("text",""))<=2200 and any(x in seed.get("text","").lower() for x in ["ctf","flag","base","xor","rsa","{","}"]):
            for item in recursive_decode_seed(seed["text"])[:5]:
                item=dict(item); item["chain_source"]=seed["source"]+" -> recursive"; item["score"]=item.get("score",0)+seed.get("weight",0)+10; chain.append(item)
    if raw:
        chain += try_decompress_bytes(raw)[:4] + xor_crib_ctf_cs(raw)[:4]
    out=[]; seen=set()
    for c in sorted(chain,key=lambda x:x.get("score",0),reverse=True):
        k=(c.get("type"),(c.get("output","") or "")[:220])
        if k not in seen:
            seen.add(k); out.append(c)
    return out[:120]
def verifyloop_refresh_analysis(report, raw_data):
    outtxt="\n".join((o.get("out") or "")[:4000] for o in report.get("outputs",[])[:80])
    combined="\n".join(report.get("strings",[])[:900])+"\n"+outtxt
    report["expert_contexts"]=expert_context_lines(combined)[:70]
    report["decoders"]=sorted(decode_candidates(combined,raw_data)+recursive_decode_seed(combined),key=lambda x:x.get("score",0),reverse=True)[:180]
    report["chain_results"]=chain_decode_report(report,raw_data)
    report["structured_clues"]=detect_structured_clues(combined[:22000]+"\n"+"\n".join((c.get("output","") or "")[:1500] for c in report.get("chain_results",[])[:30]))
    report["hypotheses"]=classify_workflow_hypotheses(report)
    return report
def cl_run_self_checks():
    """Fast local regression checks. Uses direct pattern functions plus one full project smoke."""
    results=[]; temp_ids=[]
    import base64 as _b64
    try:
        # Direct multi-layer.
        flag=b"ctf_cs{selfcheck_multi_layer_ok}"
        layer1=_b64.b64encode(flag).decode()
        layer2=layer1.encode().hex()
        layer3=_b64.b64encode(layer2.encode()).decode()
        direct=dp_raw_transform_bfs("selfcheck","blob="+layer3,max_depth=6,beam=60)
        results.append({"name":"direct_multi_layer_base64_hex_base64","ok":"ctf_cs{selfcheck_multi_layer_ok}" in json.dumps(direct),"flags":fast_flag_matches(json.dumps(direct),limit=10)})
        # Direct XOR.
        plain=b"noise::ctf_cs{selfcheck_xor_crib_ok}::end"; key=b"k3y"
        enc=bytes(b ^ key[i%len(key)] for i,b in enumerate(plain))
        xo=dp_xor_key_from_crib(enc)
        results.append({"name":"direct_aligned_repeating_xor_crib","ok":"ctf_cs{selfcheck_xor_crib_ok}" in json.dumps(xo),"flags":fast_flag_matches(json.dumps(xo),limit=10)})
        # Direct JWT.
        h=_b64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        p=_b64.urlsafe_b64encode(b'{"msg":"ctf_cs{selfcheck_jwt_ok}"}').decode().rstrip("=")
        jw=dp_jwt_decode("token="+h+"."+p+".")
        results.append({"name":"direct_jwt_payload_decode","ok":"ctf_cs{selfcheck_jwt_ok}" in json.dumps(jw),"flags":fast_flag_matches(json.dumps(jw),limit=10)})
        # One full project smoke for end-to-end path.
        flag=b"ctf_cs{selfcheck_project_ok}"
        l1=_b64.b64encode(flag).decode(); l2=l1.encode().hex(); l3=_b64.b64encode(l2.encode()).decode()
        pid=cl_build_temp_project(BASE,"project_multi",[("multi.txt","format ctf_cs{...}\nblob="+l3,"text")])
        temp_ids.append(pid); analyze_project(pid); rep=jread(report_path(pid),{})
        results.append({"name":"project_end_to_end_multi_layer","ok":"ctf_cs{selfcheck_project_ok}" in cl_flag_set(rep.get("summary",{})),"flags":cl_flag_set(rep.get("summary",{}))})
        passed=sum(1 for r in results if r["ok"])
        return {"ok":passed==len(results),"passed":passed,"total":len(results),"results":results}
    finally:
        for pid in temp_ids:
            try: shutil.rmtree(pdir(pid), ignore_errors=True)
            except Exception: pass
def cl_clean_flag_list(text):
    vals=fast_flag_matches(str(text or ""), limit=40)
    return [v for v in vals if smartsolve_strict_target_flag_ok(v)][:20]
def cl_run_self_checks():
    """Fast local regression checks. Creates one temporary project, deletes it, and shows only strict flags."""
    results=[]; temp_ids=[]
    import base64 as _b64
    try:
        flag=b"ctf_cs{selfcheck_multi_layer_ok}"
        layer1=_b64.b64encode(flag).decode()
        layer2=layer1.encode().hex()
        layer3=_b64.b64encode(layer2.encode()).decode()
        direct=dp_raw_transform_bfs("selfcheck","blob="+layer3,max_depth=6,beam=60)
        results.append({"name":"direct_multi_layer_base64_hex_base64","ok":"ctf_cs{selfcheck_multi_layer_ok}" in json.dumps(direct),"flags":cl_clean_flag_list(json.dumps(direct))})
        plain=b"noise::ctf_cs{selfcheck_xor_crib_ok}::end"; key=b"k3y"
        enc=bytes(b ^ key[i%len(key)] for i,b in enumerate(plain))
        xo=dp_xor_key_from_crib(enc)
        results.append({"name":"direct_aligned_repeating_xor_crib","ok":"ctf_cs{selfcheck_xor_crib_ok}" in json.dumps(xo),"flags":cl_clean_flag_list(json.dumps(xo))})
        h=_b64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        p=_b64.urlsafe_b64encode(b'{"msg":"ctf_cs{selfcheck_jwt_ok}"}').decode().rstrip("=")
        jw=dp_jwt_decode("token="+h+"."+p+".")
        results.append({"name":"direct_jwt_payload_decode","ok":"ctf_cs{selfcheck_jwt_ok}" in json.dumps(jw),"flags":cl_clean_flag_list(json.dumps(jw))})
        flag=b"ctf_cs{selfcheck_project_ok}"
        l1=_b64.b64encode(flag).decode(); l2=l1.encode().hex(); l3=_b64.b64encode(l2.encode()).decode()
        pid=cl_build_temp_project(BASE,"project_multi",[("multi.txt","format ctf_cs{...}\nblob="+l3,"text")])
        temp_ids.append(pid); analyze_project(pid); rep=jread(report_path(pid),{})
        results.append({"name":"project_end_to_end_multi_layer","ok":"ctf_cs{selfcheck_project_ok}" in cl_flag_set(rep.get("summary",{})),"flags":cl_flag_set(rep.get("summary",{}))})
        passed=sum(1 for r in results if r["ok"])
        return {"ok":passed==len(results),"passed":passed,"total":len(results),"results":results}
    finally:
        for pid in temp_ids:
            try: shutil.rmtree(pdir(pid), ignore_errors=True)
            except Exception: pass
PRIMARY_FLAG_RE = re.compile(r"\bctf_cs\{[^}\r\n]{1,180}\}", re.I)
ALT_CTF_RE = re.compile(r"\bctf_[a-z0-9]{2,6}\{[^}\r\n]{1,180}\}", re.I)
def vf_primary_flags(text, limit=80, scan_limit=50000):
    text = str(text or "")[:scan_limit]
    hits=[]; seen=set()
    for m in PRIMARY_FLAG_RE.finditer(text):
        cand=m.group(0)
        k=cand.lower()
        if k not in seen:
            seen.add(k); hits.append(cand)
            if len(hits)>=limit: break
    return hits
def fast_flag_matches(text, limit=20, scan_limit=9000):
    return vf_primary_flags(text, limit=limit, scan_limit=scan_limit)
def normalize_flag_candidate(flag):
    flag=str(flag or "").strip()
    m=PRIMARY_FLAG_RE.search(flag)
    if m: return m.group(0)
    return flag[:300]
def dp_flag_score(flag):
    flag=str(flag or "").strip()
    if not PRIMARY_FLAG_RE.fullmatch(flag):
        return -100
    inner=flag_inner(flag)
    score=0
    if 6 <= len(inner) <= 96: score += 40
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_\-:.+]{4,120}", inner or ""): score += 60
    if "_" in inner or "-" in inner or "." in inner or ":" in inner or "+" in inner: score += 20
    if any(w in inner.lower() for w in SMARTSOLVE_NOISE_WORDS): score -= 100
    if any(ord(c)<32 or ord(c)>126 for c in inner): score -= 120
    if "ctf_cs" in inner.lower(): score -= 90
    return score
def smartsolve_strict_target_flag_ok(flag, meta=None):
    return dp_flag_score(flag) >= 75
def vf_alt_ctf_candidates(text, limit=60, scan_limit=50000):
    text=str(text or "")[:scan_limit]
    out=[]; seen=set()
    for m in ALT_CTF_RE.finditer(text):
        cand=m.group(0)
        if cand.lower().startswith("ctf_cs{"):
            continue
        k=cand.lower()
        if k not in seen:
            seen.add(k); out.append(cand)
            if len(out)>=limit: break
    return out
def vf_answer_score(text, source=""):
    s=str(text or "").strip()
    if not s or len(s)<3 or len(s)>280:
        return 0
    low=s.lower()
    score=0
    if PRIMARY_FLAG_RE.search(s): score += 300
    if re.fullmatch(r"[a-fA-F0-9]{64}", s): score += 145
    if re.fullmatch(r"[a-fA-F0-9]{32,40}", s): score += 95
    if re.fullmatch(r"-?\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+", s): score += 125
    if re.fullmatch(r"[A-Za-z0-9_\-:.+]{6,96}", s): score += 38
    if any(k in low for k in ["answer","atsakymas","raktas","key","secret","slapta","password","pass:","code","kodas"]): score += 55
    if any(w in low for w in ["sample","dummy","fake","placeholder","example","format","ctf_cs{...}"]): score -= 120
    if "�" in s: score -= 80
    # OCR text can be valuable even without flag format.
    if source and "ocr" in source.lower() and len(s) >= 4:
        score += 25
    return score
def vf_add_answer(cands, value, source, why="", score_bonus=0):
    value=str(value or "").strip()
    if not value: return
    sc=vf_answer_score(value, source)+int(score_bonus)
    if sc>=70:
        cands.append({"value":value[:300],"source":str(source)[:180],"why":str(why)[:320],"score":sc})
def vf_collect_answer_candidates(report):
    cands=[]
    for f in report.get("flags",[]):
        vf_add_answer(cands, f, "promoted flag", "strict ctf_cs candidate", 250)
    for v in report.get("verified_flags",[]):
        vf_add_answer(cands, v.get("flag",""), "verified_flags", "; ".join(v.get("reasons",[])[:3]), int(v.get("score",0)//4))
    joined="\n".join(report.get("strings",[])[:1000])+"\n"+"\n".join((o.get("out") or "")[:5000] for o in report.get("outputs",[])[:80])
    for alt in vf_alt_ctf_candidates(joined):
        cands.append({"value":alt,"source":"alternate_ctf_like","why":"Not promoted because this toolkit promotes only ctf_cs{...}; keep as alternate answer candidate.","score":90})
    for c in report.get("chain_results",[])[:90]:
        out=(c.get("output") or "")[:3500]
        for f in vf_primary_flags(out, limit=5):
            vf_add_answer(cands, f, "chain:"+str(c.get("type","")), "decoded/derived output", int(c.get("score",0)//4)+80)
        for line in out.splitlines()[:100]:
            line=line.strip()
            if 4 <= len(line) <= 180 and any(k in line.lower() for k in ["answer","atsakymas","raktas","key","secret","slapta","password","pass","code","kodas"]):
                vf_add_answer(cands, line, "chain_context:"+str(c.get("type","")), "answer-like context line", 35)
    for p in report.get("previews",[])[:120]:
        txt=((p.get("ocr","") or "")+"\n"+(p.get("qr","") or "")).strip()
        for f in vf_primary_flags(txt, limit=4):
            vf_add_answer(cands, f, "visual_ocr_qr:"+str(p.get("name","")), "OCR/QR over generated visual artifact", int(p.get("score",0)//4)+90)
        for line in txt.splitlines()[:40]:
            line=line.strip()
            if 3 <= len(line) <= 120:
                vf_add_answer(cands, line, "visual_ocr:"+str(p.get("name","")), "OCR text; may be non-flag answer", int(p.get("score",0)//8))
    for a in report.get("artifacts",[])[:200]:
        p=Path(a.get("path",""))
        try:
            if p.exists() and p.is_file() and p.stat().st_size<800000 and (p.suffix.lower() in [".txt",".json",".log",".md",".csv",".xml"] or any(x in p.name.lower() for x in ["ocr","decoded","answer","secret","key","brief"])):
                txt=p.read_text(encoding="utf-8",errors="ignore")[:12000]
                for f in vf_primary_flags(txt, limit=5):
                    vf_add_answer(cands, f, "artifact:"+a.get("kind",""), "artifact text", int(a.get("score",0)//3)+80)
                for line in txt.splitlines()[:120]:
                    line=line.strip()
                    if 4 <= len(line) <= 180 and any(k in line.lower() for k in ["answer","atsakymas","raktas","key","secret","slapta","password","pass","code","kodas"]):
                        vf_add_answer(cands, line, "artifact_context:"+a.get("kind",""), "answer-like artifact line", int(a.get("score",0)//5))
        except Exception:
            pass
    # Deduplicate
    out=[]; seen=set()
    for x in sorted(cands,key=lambda z:z.get("score",0),reverse=True):
        k=x["value"].lower()
        if k not in seen:
            seen.add(k); out.append(x)
    return out[:160]
def vf_save_image(root, report, folder, name, img, score=30, note="VisualForge image"):
    folder.mkdir(parents=True, exist_ok=True)
    p=folder/(safe(name)+".png")
    try:
        img.save(p)
        return {"kind":"visual_filter","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"VisualForge","score":score,"note":note,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
    except Exception:
        return None
def vf_visual_lab(path, root, report):
    """Heavy visual filter gallery for tasks like camo/rotated hidden text."""
    arts=[]; previews=[]
    try:
        im=Image.open(path).convert("RGB")
    except Exception:
        return [], []
    outdir=root/"generated"/"visualforge"/safe(report.get("name",Path(path).stem))
    base=im.copy()
    W,H=base.size
    variants=[]
    def add(name, img, score=30, note=""):
        art=vf_save_image(root, report, outdir, name, img, score, note or name)
        if art:
            arts.append(art)
            # Also preview it in UI if not too many.
            previews.append({"name":"vf_"+name,"url":art["url"],"path":art["path"],"score":score,"ocr":"","qr":"","flags":[]})
    # Basic orientations.
    orientations=[("0",base),("90",base.rotate(90,expand=True)),("180",base.rotate(180,expand=True)),("270",base.rotate(270,expand=True))]
    orientations += [("flip_lr",ImageOps.mirror(base)),("flip_tb",ImageOps.flip(base))]
    # Resize huge images for processing speed.
    proc=base.copy()
    if max(proc.size)>1800:
        proc.thumbnail((1800,1800))
    # Channels.
    arr=np.array(proc)
    for idx,ch in enumerate(["R","G","B"]):
        gray=Image.fromarray(arr[:,:,idx]).convert("L")
        add(f"channel_{ch}", gray.convert("RGB"), 35, f"{ch} channel")
        add(f"channel_{ch}_autocontrast", ImageOps.autocontrast(gray).convert("RGB"), 45, f"{ch} autocontrast")
        add(f"channel_{ch}_invert", ImageOps.invert(gray).convert("RGB"), 40, f"{ch} invert")
    # HSV channels.
    try:
        hsv=proc.convert("HSV")
        h,s,v=hsv.split()
        for name,img in [("HSV_H",h),("HSV_S",s),("HSV_V",v)]:
            add(name, ImageOps.autocontrast(img).convert("RGB"), 50, name)
    except Exception:
        pass
    # Enhancement filters.
    gray=ImageOps.grayscale(proc)
    filter_imgs=[
        ("gray",gray),
        ("gray_autocontrast",ImageOps.autocontrast(gray)),
        ("invert",ImageOps.invert(gray)),
        ("edges",gray.filter(ImageFilter.FIND_EDGES)),
        ("edges_autocontrast",ImageOps.autocontrast(gray.filter(ImageFilter.FIND_EDGES))),
        ("emboss",gray.filter(ImageFilter.EMBOSS)),
        ("sharpen",gray.filter(ImageFilter.SHARPEN)),
        ("smooth_more",gray.filter(ImageFilter.SMOOTH_MORE)),
    ]
    for name,img in filter_imgs:
        add(name,img.convert("RGB"),55 if "edge" in name or "contrast" in name else 40,name)
    # Difference / high-pass style.
    try:
        blur=gray.filter(ImageFilter.GaussianBlur(radius=5))
        diff=ImageChops.difference(gray, blur)
        add("highpass_diff_blur5", ImageOps.autocontrast(diff).convert("RGB"), 70, "high-pass difference from blur")
        for r in [2,9,15]:
            blur=gray.filter(ImageFilter.GaussianBlur(radius=r))
            diff=ImageChops.difference(gray, blur)
            add(f"highpass_blur{r}", ImageOps.autocontrast(diff).convert("RGB"), 68, "high-pass")
    except Exception:
        pass
    # Thresholds + posterize/solarize.
    for t in [40,64,90,110,128,150,180,210]:
        bw=gray.point(lambda x,thr=t: 255 if x>thr else 0)
        add(f"threshold_{t}", bw.convert("RGB"), 50, f"threshold {t}")
    try:
        for bits in [2,3,4]:
            add(f"posterize_{bits}", ImageOps.posterize(proc,bits), 55, f"posterize {bits}")
        add("solarize_96", ImageOps.solarize(proc,96), 50, "solarize")
        add("solarize_128", ImageOps.solarize(proc,128), 50, "solarize")
    except Exception:
        pass
    # Local contrast and brightness sweeps.
    for c in [1.6,2.4,3.2]:
        try:
            add(f"contrast_{str(c).replace('.','_')}", ImageEnhance.Contrast(proc).enhance(c), 55, "contrast sweep")
        except Exception: pass
    for b in [0.55,0.75,1.25,1.55]:
        try:
            add(f"brightness_{str(b).replace('.','_')}", ImageEnhance.Brightness(proc).enhance(b), 48, "brightness sweep")
        except Exception: pass
    # Orientation copies for reading sideways hidden text.
    for name,img in orientations:
        thumb=img.copy()
        if max(thumb.size)>1600:
            thumb.thumbnail((1600,1600))
        add(f"orientation_{name}", thumb, 62 if name!="0" else 45, "orientation/rotation view")
    # Contact sheet for human scanning.
    try:
        thumbs=[]
        selected=arts[:48]
        for a in selected:
            p=Path(a["path"])
            img=Image.open(p).convert("RGB")
            img.thumbnail((220,160))
            tile=Image.new("RGB",(240,190),(15,25,15))
            tile.paste(img,(10,10))
            thumbs.append((tile,a["name"][:22]))
        cols=4; rows=max(1,math.ceil(len(thumbs)/cols))
        sheet=Image.new("RGB",(cols*240,rows*190),(5,10,5))
        for i,(tile,label) in enumerate(thumbs):
            sheet.paste(tile,((i%cols)*240,(i//cols)*190))
        art=vf_save_image(root, report, outdir, "00_visualforge_contact_sheet", sheet, 95, "VisualForge contact sheet")
        if art:
            arts.insert(0,art)
            previews.insert(0,{"name":"vf_contact_sheet","url":art["url"],"path":art["path"],"score":95,"ocr":"","qr":"","flags":[]})
    except Exception:
        pass
    # OCR/QR on selected high-value images, if tools installed.
    for item in previews[:60]:
        p=Path(item.get("path",""))
        if not p.exists(): continue
        if exists("tesseract"):
            try:
                o=run(["tesseract",str(p),"stdout"],15).get("out","")
                item["ocr"]=o[:2000]
                item["flags"]=vf_primary_flags(o,limit=5)
                if o.strip():
                    item["score"]=item.get("score",0)+min(60,score_text(o))
            except Exception: pass
        if exists("zbarimg"):
            try:
                q=run(["zbarimg","--quiet",str(p)],10).get("out","")
                item["qr"]=q[:1000]
                item["flags"]+=vf_primary_flags(q,limit=5)
                if q.strip():
                    item["score"]=item.get("score",0)+80
            except Exception: pass
    return arts, sorted(previews,key=lambda x:x.get("score",0),reverse=True)[:80]
def vf_postprocess(report, root):
    # Attach visual artifacts and answer candidates.
    if report.get("kind")=="image":
        arts, previews = vf_visual_lab(Path(report.get("path","")), root, report)
        existing=set(a.get("path") for a in report.get("artifacts",[]))
        for a in arts:
            if a.get("path") not in existing:
                report.setdefault("artifacts",[]).append(a); existing.add(a.get("path"))
        report.setdefault("previews",[]).extend(previews)
    # Re-run normal postprocess after visual OCR/QR.
    try:
        smartsolve_postprocess(report, root)
    except Exception:
        try: stableworkbench_apply_report_postprocess(report, root)
        except Exception: pass
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    return report
def analyze_file(pid,path,root,i,total):
    progress(pid,min(94,int((i/max(1,total))*84)+6),f"Analyzing {path.name}")
    data=readbytes(path)
    fileout=run(["file",str(path)],8).get("out","") if exists("file") else ""
    kind=detect_kind(path,fileout)
    ss=py_strings(data)
    rep={"id":uuid.uuid4().hex[:10],"name":path.name,"path":str(path),"rel":str(path.relative_to(root)),"size":path.stat().st_size,"entropy":entropy(data[:2_000_000]),"kind":kind,"file":fileout,"fingerprint":{"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest()},"flags":list(dict.fromkeys(x.decode("utf-8","replace") for x in FLAG_BYTES_RE.findall(data) if x.decode("utf-8","replace").lower().startswith("ctf_cs{"))),"strings":ss[:900],"outputs":[],"previews":[],"commands":[],"extracted":[],"expert_contexts":[],"decoders":[],"chain_results":[],"intermediate_files":[],"findings":[],"next_steps":[],"hypotheses":[],"structured_clues":[],"agent_runs":[],"agent_files":[],"transformations":[],"verifyloop":{},"verified_flags":[],"promoted_children":[],"artifacts":[],"recipe_runs":[],"artifact_graph":{},"candidate_health":{},"answer_candidates":[]}
    if kind=="archive":
        rep["extracted"]=extract_archive(path,root/"files")
    if kind=="image":
        pv,outs=image_lab(path,root)
        rep["previews"]+=pv
        rep["outputs"]+=outs
        for v in pv:
            for f in v.get("flags",[]):
                if f.lower().startswith("ctf_cs{") and f not in rep["flags"]: rep["flags"].append(f)
    if kind=="media" and exists("ffmpeg"):
        spdir=root/"generated"/"media"/path.stem; spdir.mkdir(parents=True,exist_ok=True); sp=spdir/"spectrogram.png"
        r=run(["ffmpeg","-y","-i",str(path),"-lavfi","showspectrumpic=s=1600x900",str(sp)],45)
        rep["outputs"].append({"tool":"spectrogram","ok":r["ok"],"cmd":r["cmd"],"out":r["out"]})
        if sp.exists(): rep["previews"].append({"name":"spectrogram","url":"/api/raw?path="+str(sp),"path":str(sp),"score":15})
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
        for mf in vf_primary_flags(r.get("out",""), limit=20):
            if mf not in rep["flags"]: rep["flags"].append(mf)
    rep["verifyloop"]=verifyloop_run_tools(pid,path,rep,root)
    verifyloop_refresh_analysis(rep,data)
    rep["transformations"]=execute_transform_agents(rep,root,data)
    rep["intermediate_files"]=(rep.get("intermediate_files",[])+rep.get("transformations",[]))[:320]
    write_intermediate_files(rep,root)
    rep["agent_runs"],rep["agent_files"]=run_agent_forge(rep,root)
    rep["intermediate_files"]=(rep.get("intermediate_files",[])+rep.get("agent_files",[]))[:320]
    verifyloop_scan_transform_files(rep)
    verifyloop_refresh_analysis(rep,data)
    if "deeppattern_enhance" in globals():
        deeppattern_enhance(rep,root,data)
    apply_verified_flags(rep)
    verifyloop_promote_artifacts(root,rep)
    rep["findings"]=rank_findings(rep)
    rep["next_steps"]=next_steps(rep)
    vf_postprocess(rep,root)
    return rep
