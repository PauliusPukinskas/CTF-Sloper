# Auto-split from sloper_legacy_monolith.py lines 9647-...
def rf_extract_immediate_sequences_from_disasm(disasm):
    """Fallback: collect all 0xNN immediates near each other in functions."""
    vals=[]
    for line in str(disasm or "").splitlines():
        # Ignore addresses/opcode column by using text after tab if possible.
        asm=line.split("\t")[-1] if "\t" in line else line
        for m in re.finditer(r"(?<![A-Za-z0-9])0x([0-9a-fA-F]{1,2})(?![A-Za-z0-9])", asm):
            v=int(m.group(1),16)
            vals.append(v)
    out=[]
    # Sliding windows over small immediates.
    for n in range(6, min(80,len(vals))+1):
        for i in range(0, len(vals)-n+1):
            seq=vals[i:i+n]
            # Need some nontrivial variation and likely obfuscated bytes.
            if len(set(seq))>=4:
                out.append({"type":"all_small_immediates_window","values":seq,"start_index":i})
                if len(out)>200: return out
    return out
def rf_reverse_immediate_agent(report, root, data, text):
    p=Path(report.get("path",""))
    if not p.exists():
        return []
    if report.get("kind") not in ["binary","generic","python_bytecode"] and p.suffix.lower() not in [".elf",".exe",".bin",".so",".dll",""]:
        return []
    disasm=""
    section_dump=""
    # Prefer objdump if available.
    try:
        if exists("objdump"):
            r=run(["objdump","-d","-Mintel",str(p)],20)
            disasm=r.get("out","")[:4_000_000]
            report.setdefault("outputs",[]).append({"tool":"reverseforge_objdump_disasm","ok":r.get("ok"),"cmd":r.get("cmd"),"out":disasm[:120000]})
            rs=run(["objdump","-s",str(p)],15)
            section_dump=rs.get("out","")[:2_000_000]
    except Exception as e:
        try: msf_trace(report,"ReverseForge objdump failed",str(e),0)
        except Exception: pass
    if not disasm and not section_dump:
        return []
    arrays=[]
    arrays += rf_extract_stack_immediate_arrays(disasm)
    arrays += rf_extract_rodata_hex_sequences(section_dump)
    # Fallback only if no structured arrays.
    if not arrays:
        arrays += rf_extract_immediate_sequences_from_disasm(disasm)[:60]
    candidates=[]
    for a in arrays[:100]:
        seq=a.get("values",[])
        if not (6<=len(seq)<=2048): continue
        decs=rf_deobfuscate_byte_sequence(seq, a.get("type","array"))
        for d in decs[:20]:
            cand={**d,"array_type":a.get("type"),"array_meta":{k:v for k,v in a.items() if k not in ["values","lines"]},"input_hex":bytes(seq[:256]).hex()}
            if a.get("lines"): cand["lines"]=a.get("lines")[:20]
            candidates.append(cand)
    # Dedup, prefer flags/braced body.
    out=[]; seen=set()
    for c in sorted(candidates,key=lambda x:x.get("score",0),reverse=True):
        txt=c.get("text","")
        k=(c.get("method"),c.get("key"),txt[:160])
        if k in seen: continue
        seen.add(k); out.append(c)
        if len(out)>=120: break
    if not out:
        return []
    art=rf_art(root,report,"reverse_immediate_deobfuscation_candidates.json",json.dumps(out,indent=2,ensure_ascii=False),"reverseforge_immediate_deobfuscation",260,"Static immediate arrays decoded with XOR/ADD/SUB/ROL/ROR/NOT.")
    for c in out[:40]:
        txt=c.get("text","").strip()
        flags=[ux_canonical_flag(f) for f in c.get("flags",[]) if smartsolve_strict_target_flag_ok(f)]
        # Also derive from braced body after JSON serialization.
        for f in rf_canonical_from_decoded_text(txt):
            if f not in flags:
                flags.append(f)
        for f in flags:
            if f not in report.setdefault("flags",[]):
                report["flags"].append(f)
            # Make evidence very explicit: artifact + trace mention exact flag.
            try: msf_trace(report,"ReverseImmediateAgent flag",f"{c.get('array_type')} -> {c.get('method')} {c.get('key')} -> {txt!r} -> {f}",320,art.get("path") if art else "",f)
            except Exception: pass
            report.setdefault("answer_candidates",[]).append({"value":f,"source":"ReverseImmediateAgent","why":f"Decoded from static immediate array using {c.get('method')} key={c.get('key')}.","score":360})
        if not flags and re.search(r"\{[A-Za-z0-9_\-:.+]{4,120}\}", txt):
            body=re.search(r"\{([A-Za-z0-9_\-:.+]{4,120})\}", txt).group(1)
            sugg=f"ctf_cs{{{body}}}"
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":txt,"suggested_flag":sugg,"source":"ReverseImmediateAgent","score":300,"why":f"Decoded braced body from static immediate array using {c.get('method')} key={c.get('key')}."})
            report.setdefault("answer_candidates",[]).append({"value":txt,"source":"ReverseImmediateAgent","why":"Decoded braced body; wrapper suggested.","score":280})
    try: msf_trace(report,"ReverseImmediateAgent",f"{len(arrays)} arrays scanned; {len(out)} decode candidates",230,art.get("path") if art else "")
    except Exception: pass
    return [art] if art else []
_prev_vf_postprocess_v39 = vf_postprocess
def vf_postprocess(report, root):
    report=_prev_vf_postprocess_v39(report, root)
    data=b""
    try: data=Path(report.get("path","")).read_bytes()[:12_000_000]
    except Exception: pass
    p=Path(report.get("path",""))
    if report.get("kind") in ["binary","generic","python_bytecode"] or p.suffix.lower() in [".elf",".exe",".bin",".so",".dll",""]:
        try:
            rf_reverse_immediate_agent(report,root,data,data[:250000].decode("utf-8","ignore"))
        except Exception as e:
            try: msf_trace(report,"ReverseImmediateAgent failed",str(e),0)
            except Exception: pass
    # Final promotion/evidence refresh.
    promoted=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        if wf_flag_has_solve_evidence(report,f):
            promoted.append(f)
    report["flags"]=promoted
    report["weak_flag_candidates"]=[x for x in report.get("weak_flag_candidates",[]) if str(x.get("flag","")).lower() not in {f.lower() for f in promoted}]
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: pass
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    return report
_prev_project_summary_v39 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v39(reports, meta)
    # Put ReverseForge artifacts first.
    arts=summary.get("artifacts",[])
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "reverseforge" in txt: s+=800
        if "immediate" in txt or "deobfuscation" in txt: s+=300
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(arts,key=pri,reverse=True)[:1600]
    if any("ReverseImmediateAgent" in str(x) for x in summary.get("solve_trace",[])):
        summary.setdefault("workflow_steps",[]).insert(0,{"priority":100,"step":"Review ReverseImmediateAgent result.","why":"A static encoded immediate array was decoded; likely reverse challenge path."})
    return summary
def xor_crib_ctf_cs(data):
    """Fast bounded override. Old legacy version could spend too long on full binaries."""
    outs=[]
    sample=bytes(data or b"")[:120000]
    if not sample:
        return outs
    for crib in [b"ctf_cs{", b"CTF_CS{", b"flag{", b"{"]:
        for pos in range(0, min(len(sample), 4096)):
            # derive short repeating key candidate from crib at this pos
            key=bytes(sample[pos+i]^crib[i] for i in range(min(len(crib), len(sample)-pos)))
            for kl in range(1,min(8,len(key))+1):
                k=key[:kl]
                # quick plausibility on first 4000 bytes
                dec=bytes(b^k[i%kl] for i,b in enumerate(sample[:4000]))
                sc=score_text(dec.decode("utf-8","replace"))
                if sc>82:
                    txt=bytes(b^k[i%kl] for i,b in enumerate(sample[:40000])).decode("utf-8","replace")
                    flags=vf_primary_flags(txt,limit=8,scan_limit=40000) if "vf_primary_flags" in globals() else []
                    if flags or "ctf_cs{" in txt.lower() or re.search(r"\{[A-Za-z0-9_\-:.+]{4,120}\}", txt):
                        outs.append({"type":"fast_xor_crib_key_"+k.hex(),"input":"bounded file bytes + crib","output":txt[:12000],"flags":flags,"score":sc+55})
            if len(outs)>=20:
                return sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:20]
    return sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:20]
_prev_verifyloop_refresh_v39 = verifyloop_refresh_analysis
def verifyloop_refresh_analysis(report, raw_data):
    """Fast binary-aware refresh: avoid expensive legacy recursive decoders on binaries."""
    kind=report.get("kind","")
    path=str(report.get("path","")).lower()
    is_bin = kind in ["binary","python_bytecode"] or path.endswith((".elf",".exe",".so",".dll",".bin")) or (not path.endswith((".txt",".md",".json",".csv",".log",".xml",".html",".js",".py",".php")))
    if is_bin:
        outtxt="\n".join((o.get("out") or "")[:8000] for o in report.get("outputs",[])[:40])
        combined="\n".join(report.get("strings",[])[:500])+"\n"+outtxt
        try:
            report["expert_contexts"]=expert_context_lines(combined)[:40]
        except Exception:
            report["expert_contexts"]=[]
        try:
            report["decoders"]=sorted(decode_candidates(combined[:50000],raw_data[:120000])+recursive_decode_seed(combined[:30000]),key=lambda x:x.get("score",0),reverse=True)[:80]
        except Exception:
            report["decoders"]=[]
        try:
            report["chain_results"]=chain_decode_report(report,raw_data[:160000])[:80]
        except Exception:
            report["chain_results"]=[]
        try:
            report["structured_clues"]=detect_structured_clues(combined[:50000]+"\n"+"\n".join((c.get("output","") or "")[:1200] for c in report.get("chain_results",[])[:20]))
        except Exception:
            report["structured_clues"]=[]
        return report
    return _prev_verifyloop_refresh_v39(report, raw_data)
_prev_analyze_file_v39 = analyze_file
def analyze_file(pid, path, root, i, total):
    """Wrapper: after normal file analysis, force ReverseImmediateAgent for binaries and ensure final summary sees it."""
    rep=_prev_analyze_file_v39(pid,path,root,i,total)
    try:
        p=Path(path)
        data=p.read_bytes()[:12_000_000]
        if rep.get("kind") in ["binary","generic","python_bytecode"] or p.suffix.lower() in [".elf",".exe",".bin",".so",".dll",""]:
            rf_reverse_immediate_agent(rep,root,data,data[:250000].decode("utf-8","ignore"))
            promoted=[]
            for f in list(dict.fromkeys([ux_canonical_flag(x) for x in rep.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
                if wf_flag_has_solve_evidence(rep,f):
                    promoted.append(f)
            rep["flags"]=promoted
            rep["answer_candidates"]=vf_collect_answer_candidates(rep)
            try: rep["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(rep)
            except Exception: pass
            try: af_evidence_score_candidates(rep)
            except Exception: pass
            try: rep["autopilot_review"]=ff_autopilot_review(rep)
            except Exception: pass
    except Exception as e:
        try: msf_trace(rep,"ReverseForge analyze_file wrapper failed",str(e),0)
        except Exception: pass
    return rep
def rf_canonical_from_decoded_text(txt):
    """Reverse solver promotion: only exact ctf_cs or explicit {body}; never arbitrary random body."""
    txt=str(txt or "").strip()
    hits=[]
    for f in vf_primary_flags(txt,limit=20,scan_limit=5000):
        hits.append(f)
    for m in re.finditer(r"\{([A-Za-z0-9_\-:.+]{4,120})\}", txt):
        body=m.group(1)
        cand=f"ctf_cs{{{body}}}"
        if smartsolve_strict_target_flag_ok(cand):
            hits.append(cand)
    out=[]; seen=set()
    for h in hits:
        h=ux_canonical_flag(h)
        if h.lower() not in seen:
            seen.add(h.lower()); out.append(h)
    return out
def rf_deobfuscate_byte_sequence(seq, source="sequence"):
    """Try common CTF transforms on a byte array and return ranked candidates, with stricter flag generation."""
    seq=bytes(int(x)&255 for x in seq)
    out=[]
    def add(method,key,bs):
        txt=bytes(bs).decode("utf-8","ignore")
        sc=rf_printable_score(bs)
        flags=rf_canonical_from_decoded_text(txt)
        if flags: sc+=260
        # Require braces/exact flag, or very strong readable clue.
        if sc>=220 and (flags or re.search(r"\{[A-Za-z0-9_\-:.+]{4,120}\}",txt) or any(w in txt.lower() for w in ["flag","secret","password","token"])):
            out.append({"method":method,"key":key,"text":txt,"hex":bytes(bs).hex(),"score":sc,"flags":flags,"source":source})
    add("raw",None,seq)
    for k in range(256):
        add("xor",k,bytes(b^k for b in seq))
        add("add",k,bytes((b+k)&255 for b in seq))
        add("sub",k,bytes((b-k)&255 for b in seq))
    add("not",None,bytes((~b)&255 for b in seq))
    for r in range(1,8):
        add("rol",r,bytes(rf_rotl8(b,r) for b in seq))
        add("ror",r,bytes(rf_rotr8(b,r) for b in seq))
    best=[]; seen=set()
    for c in sorted(out,key=lambda x:x.get("score",0),reverse=True):
        key=(c["method"],c.get("key"),c["text"][:160])
        if key not in seen:
            seen.add(key); best.append(c)
        if len(best)>=60: break
    return best
def rf_is_binary_path(path, data=None):
    p=Path(path)
    suf=p.suffix.lower()
    if suf in [".elf",".exe",".so",".dll",".bin",".out"] or p.name.lower() in ["calculus","chall","challenge","rev","main"]:
        return True
    if data is None:
        try: data=p.read_bytes()[:8]
        except Exception: data=b""
    return bytes(data or b"").startswith((b"\x7fELF", b"MZ"))
def rf_fast_binary_analyze_file(pid, path, root, i, total):
    p=Path(path)
    data=p.read_bytes()
    rel=str(p.relative_to(root)) if str(p).startswith(str(root)) else p.name
    report={
        "id":uuid.uuid4().hex[:10],
        "name":p.name,
        "path":str(p),
        "rel":rel,
        "kind":"binary",
        "size":len(data),
        "sha256":hashlib.sha256(data).hexdigest(),
        "md5":hashlib.md5(data).hexdigest(),
        "magic":data[:32].hex(),
        "flags":[],
        "weak_flag_candidates":[],
        "verified_flags":[],
        "verified_flags_visible":[],
        "strings":[],
        "outputs":[],
        "previews":[],
        "commands":[],
        "decoders":[],
        "chain_results":[],
        "intermediate_files":[],
        "artifacts":[],
        "transformations":[],
        "findings":[],
        "next_steps":[],
        "solve_trace":[],
        "agent_trace":[],
        "answer_candidates":[],
        "flag_wrapping_helpers":[],
        "evidence_scored_candidates":[]
    }
    # Fast metadata/tools only.
    try:
        report["strings"]=py_strings(data,limit=2500)
    except Exception:
        report["strings"]=[]
    for tool,cmd,timeout in [
        ("file",["file",str(p)],5),
        ("checksec_basic",["bash","-lc",f"checksec --file={shlex.quote(str(p))} 2>/dev/null || true"],8),
        ("readelf_header",["readelf","-h",str(p)],8),
        ("readelf_sections",["readelf","-S",str(p)],8),
        ("objdump_rodata",["objdump","-s","-j",".rodata",str(p)],8),
    ]:
        try:
            if cmd[0]=="bash" or exists(cmd[0]):
                r=run(cmd,timeout)
                report["outputs"].append({"tool":tool,"ok":r.get("ok"),"cmd":r.get("cmd"),"out":r.get("out","")[:60000]})
        except Exception:
            pass
    # Exact strings flags.
    for f in vf_primary_flags("\n".join(report["strings"]),limit=40,scan_limit=80000):
        if f not in report["flags"]: report["flags"].append(f)
    # Reverse immediate deobfuscation FIRST.
    try:
        rf_reverse_immediate_agent(report,root,data,data[:250000].decode("utf-8","ignore"))
    except Exception as e:
        try: msf_trace(report,"ReverseImmediateAgent failed",str(e),0)
        except Exception: pass
    # Optional safe static pyc/numeric if relevant.
    try:
        if p.suffix.lower()==".pyc":
            cs_pyc_decode_artifacts(root,report,data)
    except Exception:
        pass
    try:
        wf_scan_numeric_tables(data,root,report)
    except Exception:
        pass
    promoted=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        if wf_flag_has_solve_evidence(report,f):
            promoted.append(f)
    report["flags"]=promoted
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: report["flag_wrapping_helpers"]=[]
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    if report["flags"]:
        report["findings"].append({"score":400,"type":"reverseforge_flag","value":report["flags"][0],"why":"Fast binary ReverseForge path recovered evidence-backed ctf_cs flag."})
    else:
        report["next_steps"].append({"priority":95,"step":"Open ReverseForge artifacts / solve trace.","why":"Binary was processed with static immediate deobfuscation."})
    return report
_prev_analyze_file_v39_heavy = analyze_file
def analyze_file(pid, path, root, i, total):
    try:
        p=Path(path)
        head=p.read_bytes()[:16]
        if rf_is_binary_path(p, head):
            return rf_fast_binary_analyze_file(pid,path,root,i,total)
    except Exception:
        pass
    return _prev_analyze_file_v39_heavy(pid,path,root,i,total)
def rf_fast_binary_analyze_file(pid, path, root, i, total):
    import shlex as _shlex
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
    try: report["strings"]=py_strings(data,limit=2500)
    except Exception: report["strings"]=[]
    for tool,cmd,timeout in [
        ("file",["file",str(p)],5),
        ("checksec_basic",["bash","-lc",f"checksec --file={_shlex.quote(str(p))} 2>/dev/null || true"],8),
        ("readelf_header",["readelf","-h",str(p)],8),
        ("readelf_sections",["readelf","-S",str(p)],8),
        ("objdump_rodata",["objdump","-s","-j",".rodata",str(p)],8),
    ]:
        try:
            if cmd[0]=="bash" or exists(cmd[0]):
                r=run(cmd,timeout)
                report["outputs"].append({"tool":tool,"ok":r.get("ok"),"cmd":r.get("cmd"),"out":r.get("out","")[:60000]})
        except Exception:
            pass
    for f in vf_primary_flags("\n".join(report["strings"]),limit=40,scan_limit=80000):
        if f not in report["flags"]: report["flags"].append(f)
    try: rf_reverse_immediate_agent(report,root,data,data[:250000].decode("utf-8","ignore"))
    except Exception as e:
        try: msf_trace(report,"ReverseImmediateAgent failed",str(e),0)
        except Exception: pass
    try:
        if p.suffix.lower()==".pyc": cs_pyc_decode_artifacts(root,report,data)
    except Exception: pass
    try: wf_scan_numeric_tables(data,root,report)
    except Exception: pass
    promoted=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        if wf_flag_has_solve_evidence(report,f): promoted.append(f)
    report["flags"]=promoted
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: report["flag_wrapping_helpers"]=[]
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    if report["flags"]:
        report["findings"].append({"score":400,"type":"reverseforge_flag","value":report["flags"][0],"why":"Fast binary ReverseForge path recovered evidence-backed ctf_cs flag."})
    else:
        report["next_steps"].append({"priority":95,"step":"Open ReverseForge artifacts / solve trace.","why":"Binary was processed with static immediate deobfuscation."})
    return report
def rf_fast_binary_analyze_file(pid, path, root, i, total):
    import shlex as _shlex
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
    try: report["strings"]=py_strings(data,limit=2500)
    except Exception: report["strings"]=[]
    for tool,cmd,timeout in [
        ("file",["file",str(p)],5),
        ("readelf_header",["readelf","-h",str(p)],6),
        ("readelf_sections",["readelf","-S",str(p)],6),
        ("objdump_rodata",["objdump","-s","-j",".rodata",str(p)],6),
    ]:
        try:
            if exists(cmd[0]):
                r=run(cmd,timeout)
                report["outputs"].append({"tool":tool,"ok":r.get("ok"),"cmd":r.get("cmd"),"out":r.get("out","")[:50000]})
        except Exception:
            pass
    for f in vf_primary_flags("\n".join(report["strings"]),limit=40,scan_limit=80000):
        if f not in report["flags"]: report["flags"].append(f)
    # Priority agent for these easy reverse tasks.
    try: rf_reverse_immediate_agent(report,root,data,data[:250000].decode("utf-8","ignore"))
    except Exception as e:
        try: msf_trace(report,"ReverseImmediateAgent failed",str(e),0)
        except Exception: pass
    # Numeric table only when explicitly hinted, because otherwise it creates random wrappers on arbitrary binaries.
    hints=(ux_statement_text(report)+"\n"+p.name+"\n"+"\n".join(report.get("strings",[])[:80])).lower()
    if any(k in hints for k in ["numeric","numerical","coefficient","coeff","double table","float table","lentel","koef"]):
        try: wf_scan_numeric_tables(data,root,report)
        except Exception: pass
    # Keep only strict flags supported by ReverseImmediateAgent/exact string evidence.
    promoted=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        ev=report.get("flag_evidence",{}).get(f,{})
        if wf_flag_has_solve_evidence(report,f):
            sources=" ".join(report.get("flag_evidence",{}).get(f,{}).get("sources",[])).lower()
            trace=" ".join(str(x) for x in report.get("solve_trace",[])[:80]).lower()
            if ("reverseimmediateagent" in trace) or ("strings" in sources) or ("artifact" in sources):
                promoted.append(f)
    # If multiple reverse candidates survived, prefer the one with readable braced body and calc/key/flag words.
    def pf_score(f):
        inner=flag_inner(f).lower()
        s=0
        if any(w in inner for w in ["calc","flag","key","secret","pass","token","you"]): s+=200
        if "_" in inner: s+=80
        if any(ch.isdigit() for ch in inner): s+=30
        s-=max(0,len(inner)-40)
        return s
    promoted=sorted(list(dict.fromkeys(promoted)), key=pf_score, reverse=True)[:5]
    report["flags"]=promoted
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: report["flag_wrapping_helpers"]=[]
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    if report["flags"]:
        report["findings"].append({"score":500,"type":"reverseforge_flag","value":report["flags"][0],"why":"Fast binary ReverseForge path recovered evidence-backed ctf_cs flag."})
    else:
        report["next_steps"].append({"priority":95,"step":"Open ReverseForge artifacts / solve trace.","why":"Binary was processed with static immediate deobfuscation."})
    return report
def rf_flag_priority_score(f):
    inner=flag_inner(f).lower()
    s=0
    if any(w in inner for w in ["calc","flag","key","secret","pass","token","you"]): s+=220
    if "_" in inner: s+=90
    if any(ch.isdigit() for ch in inner): s+=40
    if re.search(r"[a-z]{3,}_[a-z0-9_]{3,}", inner): s+=60
    # penalize obvious repeated filler / random mixed case without meaningful words
    if re.fullmatch(r"[a-zA-Z0-9]+", inner) and len(inner)<18: s-=80
    if re.search(r"(.)\1{4,}", inner): s-=120
    s-=max(0,len(inner)-50)
    return s
def rf_filter_promoted_binary_flags(report):
    filtered=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        if not wf_flag_has_solve_evidence(report,f):
            continue
        ev=report.get("flag_evidence",{}).get(f,{})
        sources=" ".join(ev.get("sources",[])).lower()
        score=rf_flag_priority_score(f)
        if "strings" in sources:
            filtered.append(f)
        elif score>=160:
            filtered.append(f)
    return sorted(list(dict.fromkeys(filtered)), key=rf_flag_priority_score, reverse=True)[:3]
_prev_rf_fast_binary_analyze_file_v39_filter = rf_fast_binary_analyze_file
def rf_fast_binary_analyze_file(pid, path, root, i, total):
    report=_prev_rf_fast_binary_analyze_file_v39_filter(pid,path,root,i,total)
    report["flags"]=rf_filter_promoted_binary_flags(report)
    promoted=set(x.lower() for x in report["flags"])
    report["weak_flag_candidates"]=[x for x in report.get("weak_flag_candidates",[]) if str(x.get("flag","")).lower() not in promoted]
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: pass
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    report["findings"]=[x for x in report.get("findings",[]) if x.get("type")!="reverseforge_flag"]
    if report["flags"]:
        report["findings"].insert(0,{"score":520,"type":"reverseforge_flag","value":report["flags"][0],"why":"Fast binary ReverseForge path recovered high-confidence evidence-backed ctf_cs flag."})
    return report
def sf_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        msf_trace(report, "SprintForge:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SprintForge:"+str(stage),
            "detail":str(detail)[:900],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sf_art(root, report, name, content, kind="sprintforge_artifact", score=120, note=""):
    outdir=root/"generated"/"sprintforge"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"SprintForge","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sf_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sf_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sf_text_score(text):
    s=str(text or "")
    if not s:
        return 0
    low=s.lower()
    printable=sum(1 for c in s if 32<=ord(c)<127 or c in "\n\r\t")
    score=int(80*printable/max(1,len(s)))
    if vf_primary_flags(s,limit=3,scan_limit=5000): score+=350
    if re.search(r"\{[A-Za-z0-9_\-:.+]{4,120}\}",s): score+=180
    if re.search(r"[a-z0-9]{3,}_[a-z0-9_]{3,}",low): score+=80
    if any(w in low for w in ["flag","secret","raktas","slapta","calc","you","admin","password","token","vilnius","lietuva","cwe"]): score+=40
    if len(s)>=8: score+=20
    if len(s)>600: score-=30
    if "�" in s: score-=70
    return score
def sf_add_body_candidate(report, body, source, why, score=220, promote=False, artifact=None):
    body=str(body or "").strip().strip("{} \t\r\n")
    if not (4<=len(body)<=140):
        return
    body=re.sub(r"\s+","_",body)
    body=re.sub(r"[^A-Za-z0-9_\-:.+]","",body)
    if not body:
        return
    cand=f"ctf_cs{{{body}}}"
    report.setdefault("answer_candidates",[]).append({"value":body,"source":source,"why":why,"score":score})
    if not ux_statement_allows_raw_answer(report):
        report.setdefault("flag_wrapping_helpers",[]).append({"answer":body,"suggested_flag":cand,"source":source,"score":score-5,"why":why+"; wrapper ctf_cs{...} suggested."})
    if promote and smartsolve_strict_target_flag_ok(cand):
        if cand not in report.setdefault("flags",[]):
            report["flags"].append(cand)
        sf_trace(report,source,why,score,artifact,cand)
def sf_promote_from_text(report, text, source, why="", artifact=None, score=260):
    text=str(text or "")
    found=0
    for f in vf_primary_flags(text,limit=40,scan_limit=30000):
        if f not in report.setdefault("flags",[]):
            report["flags"].append(f)
        report.setdefault("answer_candidates",[]).append({"value":f,"source":source,"why":why or "strict ctf_cs in decoded text","score":score})
        sf_trace(report,source,why or "strict ctf_cs found",score,artifact,f)
        found+=1
    # explicit {body} to wrapper, but promote only if decode path is strong
    for m in re.finditer(r"\{([A-Za-z0-9_\-:.+]{4,120})\}", text):
        body=m.group(1)
        cand=f"ctf_cs{{{body}}}"
        if smartsolve_strict_target_flag_ok(cand):
            sf_add_body_candidate(report,body,source,why or "decoded braced body",score-20, promote=(score>=260), artifact=artifact)
            found+=1
    return found
def sf_route_variants(s, rows, cols):
    # Create matrices from ciphertext by row or column, read with route variants.
    s=str(s)
    if rows*cols!=len(s):
        return []
    variants=[]
    # fill row-major and read column-major variants
    mat=[list(s[i*cols:(i+1)*cols]) for i in range(rows)]
    def read_rows(m): return "".join("".join(r) for r in m)
    def read_cols(m): return "".join(m[r][c] for c in range(cols) for r in range(rows))
    def read_cols_rev(m): return "".join(m[r][c] for c in reversed(range(cols)) for r in range(rows))
    def read_cols_zigzag(m):
        out=[]
        for c in range(cols):
            rng=range(rows) if c%2==0 else reversed(range(rows))
            for r in rng: out.append(m[r][c])
        return "".join(out)
    def read_rows_zigzag(m):
        out=[]
        for r in range(rows):
            row=m[r] if r%2==0 else list(reversed(m[r]))
            out+=row
        return "".join(out)
    def spiral(m):
        top=0; bot=rows-1; left=0; right=cols-1; out=[]
        while top<=bot and left<=right:
            for c in range(left,right+1): out.append(m[top][c])
            top+=1
            for r in range(top,bot+1): out.append(m[r][right])
            right-=1
            if top<=bot:
                for c in range(right,left-1,-1): out.append(m[bot][c])
                bot-=1
            if left<=right:
                for r in range(bot,top-1,-1): out.append(m[r][left])
                left+=1
        return "".join(out)
    readers=[("row",read_rows),("col",read_cols),("col_rev",read_cols_rev),("col_zigzag",read_cols_zigzag),("row_zigzag",read_rows_zigzag),("spiral",spiral)]
    transforms=[
        ("fill_row",mat),
        ("fill_row_revrows",list(reversed(mat))),
        ("fill_row_revcols",[list(reversed(r)) for r in mat]),
        ("fill_row_transpose",[[mat[r][c] for r in range(rows)] for c in range(cols)] if rows!=cols else [[mat[r][c] for r in range(rows)] for c in range(cols)])
    ]
    for tname,m in transforms:
        rr=len(m); cc=len(m[0]) if m else 0
        if rr==rows and cc==cols:
            for rname,fn in readers:
                try: variants.append((tname+"_"+rname,fn(m)))
                except Exception: pass
        else:
            # transpose dims
            for name,fn in [
                ("row","".join("".join(r) for r in m)),
                ("col","".join(m[r][c] for c in range(cc) for r in range(rr))),
            ]:
                variants.append((tname+"_"+name,fn))
    return variants
def sf_transposition_agent(report, root, text):
    """General route/transposition brute helper for crypto text files."""
    raw=str(text or "")
    # Use longest compact ciphertext-like line.
    lines=[x.strip() for x in raw.splitlines() if len(x.strip())>=16]
    cands=[]
    for line in lines:
        # strip labels, keep symbols because flags may contain braces/underscores
        candidate=line
        if ":" in candidate and len(candidate.split(":",1)[1])>=16:
            candidate=candidate.split(":",1)[1].strip()
        if len(candidate)>500:
            continue
        cands.append(candidate)
    if not cands:
        return []
    outs=[]
    for s in cands[:8]:
        L=len(s)
        factors=[]
        for r in range(2,min(40,L)+1):
            if L%r==0:
                c=L//r
                if 2<=c<=80:
                    factors.append((r,c))
        for r,c in factors[:80]:
            for name,out in sf_route_variants(s,r,c):
                sc=sf_text_score(out)
                # Also try reverse of output
                for nm,txt in [(name,out),(name+"_rev",out[::-1])]:
                    sc2=sf_text_score(txt)
                    if sc2>=150:
                        flags=vf_primary_flags(txt,limit=10,scan_limit=5000)
                        outs.append({"method":nm,"rows":r,"cols":c,"output":txt,"score":sc2,"flags":flags})
    # Dedup
    best=[]; seen=set()
    for x in sorted(outs,key=lambda y:y.get("score",0),reverse=True):
        k=x["output"][:160]
        if k not in seen:
            seen.add(k); best.append(x)
        if len(best)>=120: break
    if not best:
        return []
    art=sf_art(root,report,"transposition_route_candidates.json",json.dumps(best,indent=2,ensure_ascii=False),"sprintforge_transposition_candidates",185,"Route/rail/column transposition candidates from text.")
    for x in best[:30]:
        sf_promote_from_text(report,x.get("output",""),"SprintForge TranspositionAgent",f"{x.get('method')} {x.get('rows')}x{x.get('cols')}",art.get("path") if art else "",x.get("score",0)+40)
    sf_trace(report,"TranspositionAgent",f"{len(best)} route/transposition candidates",180,art.get("path") if art else "")
    return [art] if art else []
def sf_openSSH_randomart_to_bits(text):
    """Convert randomart-like key boxes into a compact string/bits artifact for human review."""
    lines=[]
    for line in str(text or "").splitlines():
        if "|" in line:
            body=line.split("|",1)[1].rsplit("|",1)[0]
            lines.append(body)
    if not lines:
        return None
    mapping={".":"0"," ":"0","o":"1","*":"1","#":"1","=":"1","+":"1","S":"1","E":"1","@":"1"}
    bits="".join(mapping.get(ch,"0") for row in lines for ch in row)
    coords=[]
    for y,row in enumerate(lines):
        for x,ch in enumerate(row):
            if ch not in [" ","."]:
                coords.append((x,y,ch))
    return {"rows":lines,"bits":bits,"coords":coords,"coord_string":";".join(f"{x},{y},{ch}" for x,y,ch in coords)}
def sf_key_text_agent(report, root, text):
    if "|" not in str(text) and "[key]" not in str(text).lower():
        return []
    obj=sf_openSSH_randomart_to_bits(text)
    if not obj:
        return []
    art=sf_art(root,report,"randomart_key_features.json",json.dumps(obj,indent=2,ensure_ascii=False),"sprintforge_randomart_key_features",125,"Extracted bits/coordinates from randomart-like key. Use with message transposition if needed.")
    sf_trace(report,"RandomArtKeyAgent",f"{len(obj.get('coords',[]))} non-empty coordinates extracted",125,art.get("path") if art else "")
    return [art] if art else []
def sf_docx_carve_agent(report, root, data):
    """Carve embedded OOXML/DOCX zip from raw disk/image bytes."""
    data=bytes(data or b"")
    arts=[]
    # find PK zip headers and try valid zip, then docx xml strings
    for idx in [m.start() for m in re.finditer(b"PK\x03\x04", data[:80_000_000])][:80]:
        raw=data[idx:]
        try:
            import io, zipfile as _zipfile
            bio=io.BytesIO(raw)
            if not _zipfile.is_zipfile(bio):
                continue
            bio.seek(0)
            with _zipfile.ZipFile(bio) as z:
                names=z.namelist()
                if not any(n.startswith("word/") or n=="[Content_Types].xml" for n in names):
                    continue
                outdir=root/"generated"/"sprintforge"/safe(report.get("name","file"))/f"carved_docx_{idx}"
                outdir.mkdir(parents=True,exist_ok=True)
                docx=outdir/"carved.docx"
                # rebuild minimal zip from members
                with _zipfile.ZipFile(docx,"w",_zipfile.ZIP_DEFLATED) as outz:
                    for n in names:
                        try: outz.writestr(n,z.read(n))
                        except Exception: pass
                text=""
                for n in names:
                    if n.startswith("word/") and n.endswith(".xml"):
                        try:
                            xml=z.read(n).decode("utf-8","ignore")
                            text += re.sub(r"<[^>]+>"," ",xml)+"\n"
                        except Exception: pass
                txtp=outdir/"carved_docx_text.txt"
                txtp.write_text(text,encoding="utf-8",errors="ignore")
                art={"kind":"sprintforge_carved_docx","name":docx.name,"path":str(docx),"url":"/api/raw?path="+str(docx),"source":"SprintForge","score":230,"note":f"Carved DOCX/OOXML ZIP at byte offset {idx}","exists":True,"size":docx.stat().st_size,"file":report.get("rel","")}
                report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art)
                txtart={"kind":"sprintforge_carved_docx_text","name":txtp.name,"path":str(txtp),"url":"/api/raw?path="+str(txtp),"source":"SprintForge","score":250,"note":"Text extracted from carved DOCX XML.","exists":True,"size":txtp.stat().st_size,"file":report.get("rel","")}
                report.setdefault("artifacts",[]).append(txtart); report.setdefault("transformations",[]).append(txtart); arts.append(txtart)
                sf_promote_from_text(report,text,"SprintForge DocxCarver","text from carved DOCX",str(txtp),260)
        except Exception:
            pass
    if arts:
        sf_trace(report,"DocxCarver",f"{len(arts)} DOCX carve artifacts",230,arts[0].get("path"))
    return arts
def sf_tail_embedded_agent(report, root, data):
    """Extract tail data after common image/file end markers and try decompress/extract."""
    data=bytes(data or b"")
    markers=[(b"IEND\xaeB`\x82",4,"png_iend"),(b"\xff\xd9",2,"jpeg_eoi")]
    arts=[]
    for marker,adjust,name in markers:
        idx=data.find(marker)
        if idx>=0:
            end=idx+len(marker)
            tail=data[end:]
            if len(tail)>=16:
                art=sf_art(root,report,f"{name}_tail.bin",tail,"sprintforge_tail_data",165,f"Data appended after {name} marker.")
                if art: arts.append(art)
                # Try zlib/gzip/bz2/lzma/raw zip parsing
                try:
                    af_decompress_recursive(report,root,tail,name+"_tail",0,3)
                except Exception: pass
                try:
                    af_parse_embedded_files(report,root,tail,name+"_tail")
                except Exception: pass
                txt=tail[:200000].decode("utf-8","ignore")
                if txt: sf_promote_from_text(report,txt,"SprintForge TailData","text in appended tail",art.get("path") if art else "",190)
    return arts
def sf_nested_archive_agent(report, root, data):
    """Generic recursive archive extraction plus password hints from Morse/comments."""
    arts=[]
    p=Path(report.get("path",""))
    # Existing archive helpers
    try: arts += cs_archive_extract_artifacts(root,report,data)
    except Exception: pass
    try: af_parse_embedded_files(report,root,data,report.get("name","file"))
    except Exception: pass
    try: af_decompress_recursive(report,root,data,report.get("name","file"),0,3)
    except Exception: pass
    # Collect possible passwords from text/morse/exif outputs/artifacts.
    joined="\n".join(report.get("strings",[])[:500])+"\n"+"\n".join((o.get("out") or "")[:5000] for o in report.get("outputs",[])[:80])
    try:
        for name,out in cs_morse_hex_url_chain(joined):
            report.setdefault("chain_results",[]).append({"type":"sprintforge_"+name,"input":"archive metadata/strings","output":out,"flags":vf_primary_flags(out,limit=5),"score":150,"chain_source":"SprintForge archive password clue"})
            sf_promote_from_text(report,out,"SprintForge ArchivePassword","morse/hex/url password clue",None,160)
    except Exception: pass
    # Try empty/common passwords for zip artifacts if 7z is installed.
    zips=[]
    for a in report.get("artifacts",[])[:200]:
        pp=Path(a.get("path",""))
        if pp.suffix.lower()==".zip" and pp.exists():
            zips.append(pp)
    if p.suffix.lower()==".zip" and p.exists():
        zips.append(p)
    passwords=["","password","secret","slapta","raktas","ctf","cyber","sprint"]
    for z in zips[:20]:
        for pw in passwords:
            try:
                if exists("7z"):
                    outdir=root/"generated"/"sprintforge"/safe(report.get("name","file"))/("zip_extract_"+safe(z.stem)+"_"+safe(pw or "empty"))
                    outdir.mkdir(parents=True,exist_ok=True)
                    cmd=["7z","x","-y",f"-p{pw}",f"-o{outdir}",str(z)]
                    r=run(cmd,10)
                    if r.get("ok") and any(outdir.rglob("*")):
                        art=sf_art(root,report,f"zip_extract_{safe(z.stem)}_{safe(pw or 'empty')}.txt",r.get("out",""),"sprintforge_zip_password_extract",180,f"ZIP extracted with password candidate {pw!r}.")
                        sf_trace(report,"ZipPasswordAgent",f"{z.name} extracted with password {pw!r}",180,art.get("path") if art else "")
                        break
            except Exception:
                pass
    return arts
