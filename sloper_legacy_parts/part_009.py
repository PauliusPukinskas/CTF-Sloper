# Auto-split from sloper_legacy_monolith.py lines 7844-...
def project_summary(reports, meta):
    # Wrap existing project summary with weak flags and solve trace aggregation.
    flags=[]; weak=[]; verified_map={}; kinds={}; evidence=[]; chains=[]; actions=[]; missing=[]; agents=[]; transforms=[]; verifyloops=[]; artifacts=[]; recipes=[]; graphs=[]; answers=[]; wrappers=[]; reviews=[]; traces=[]; evscored=[]; solve_traces=[]
    for r in reports:
        kinds[r.get("kind","?")]=kinds.get(r.get("kind","?"),0)+1
        for tr in r.get("solve_trace",[])[:160]:
            solve_traces.append({"file":r.get("rel"),**tr})
        for tr in r.get("agent_trace",[])[:120]:
            traces.append({"file":r.get("rel"),**tr})
        for wf in r.get("weak_flag_candidates",[])[:40]:
            weak.append({"file":r.get("rel"),**wf})
        for ev in r.get("evidence_scored_candidates",[])[:80]:
            evscored.append({"file":r.get("rel"),**ev})
        for v in r.get("verified_flags_visible",[])[:80]:
            key=(v.get("flag") or "").lower(); vv={"file":r.get("rel"),**v}
            if key and (key not in verified_map or vv.get("score",0)>verified_map[key].get("score",0)): verified_map[key]=vv
        for f in r.get("flags",[])[:100]:
            if smartsolve_strict_target_flag_ok(f): flags.append({"file":r.get("rel"),"flag":f,"score":999,"status":"promoted_with_evidence"})
        for ans in r.get("answer_candidates",[])[:120]: answers.append({"file":r.get("rel"),**ans})
        for h in r.get("flag_wrapping_helpers",[])[:80]: wrappers.append({"file":r.get("rel"),**h})
        for f in r.get("findings",[])[:60]:
            if not is_noisy_candidate_text(f.get("value",""),f.get("why",""),f.get("type","")): evidence.append({"file":r.get("rel"),**f})
        for c in r.get("chain_results",[])[:60]:
            out=(c.get("output","") or "")[:900]
            if c.get("score",0)>70 and not is_noisy_candidate_text(out,c.get("type",""),"chain"):
                chains.append({"file":r.get("rel"),"type":c.get("type"),"source":c.get("chain_source"),"score":c.get("score"),"output":out})
        for s in r.get("next_steps",[])[:8]: actions.append({"file":r.get("rel"),**s})
        for a in r.get("agent_runs",[])[:8]: agents.append({"file":r.get("rel"),"kind":r.get("kind"),**a})
        for t in r.get("transformations",[])[:100]: transforms.append({"file":r.get("rel"),**t})
        if r.get("verifyloop"): verifyloops.append({"file":r.get("rel"),"kind":r.get("kind"),**r.get("verifyloop",{})})
        for art in r.get("artifacts",[])[:400]: artifacts.append(art)
        for rec in r.get("recipe_runs",[])[:10]: recipes.append({"file":r.get("rel"),"kind":r.get("kind"),**rec})
        if r.get("artifact_graph"): graphs.append({"file":r.get("rel"),"graph":r.get("artifact_graph")})
        for o in r.get("outputs",[])[:80]:
            if not o.get("ok") and "not installed" in (o.get("out","").lower()): missing.append((o.get("out","").split() or ["unknown"])[0])
    def dedupe_by(items,keyfn,scorefn=lambda x:x.get("score",0)):
        mp={}
        for x in items:
            k=keyfn(x)
            if k and (k not in mp or scorefn(x)>scorefn(mp[k])): mp[k]=x
        return list(mp.values())
    flags=sorted(dedupe_by(flags,lambda x:(x.get("flag") or "").lower()),key=lambda x:x.get("score",0),reverse=True)[:100]
    weak=sorted(dedupe_by(weak,lambda x:(x.get("flag") or "").lower(), lambda x:x.get("support",0)), key=lambda x:x.get("support",0), reverse=True)[:120]
    answers=sorted(dedupe_by(answers,lambda x:(x.get("value") or "").lower()),key=lambda x:x.get("score",0),reverse=True)[:280]
    wrappers=sorted(dedupe_by(wrappers,lambda x:(x.get("suggested_flag") or "").lower()),key=lambda x:x.get("score",0),reverse=True)[:140]
    evscored=sorted(dedupe_by(evscored,lambda x:(x.get("value") or "").lower(), lambda x:x.get("evidence_score",0)), key=lambda x:x.get("evidence_score",0), reverse=True)[:180]
    verified_all=sorted(verified_map.values(),key=lambda x:x.get("score",0),reverse=True)[:120]
    artifacts=sorted(artifacts,key=lambda x:(x.get("exists",False),x.get("score",0),x.get("size",0)),reverse=True)[:1400]
    evidence=sorted(evidence,key=lambda x:x.get("score",0),reverse=True)[:160]
    chains=sorted(chains,key=lambda x:x.get("score",0) or 0,reverse=True)[:160]
    recipes=sorted(recipes,key=lambda x:x.get("score",0),reverse=True)[:180]
    exact=[f for f in flags if "ctf_cs{" in f.get("flag","").lower()]
    workflow=[]
    if exact: workflow.append({"priority":100,"step":"Submit/check top strict ctf_cs flag with solve evidence.","why":"Flag has chain/artifact/trace support."})
    elif weak: workflow.append({"priority":98,"step":"Inspect Weak Flag Candidates, but do not trust them yet.","why":"They look like flags but lack enough solve evidence."})
    elif answers: workflow.append({"priority":97,"step":"Open Answer Candidates and Flag Wrapping Helpers.","why":"No strict flag found; likely answer may need wrapping as ctf_cs{answer}."})
    if solve_traces: workflow.append({"priority":96,"step":"Open Solve Trace.","why":"WriteupForge shows the multi-step reasoning path and created artifacts."})
    if evscored: workflow.append({"priority":95,"step":"Open Evidence Scores.","why":"Candidates are ranked by supporting sources."})
    priority=sorted([{"file":r.get("rel"),"kind":r.get("kind"),"flags":len(r.get("flags",[])),"weak_flags":len(r.get("weak_flag_candidates",[])),"answers":len(r.get("answer_candidates",[])),"wrappers":len(r.get("flag_wrapping_helpers",[])),"artifacts":len(r.get("artifacts",[])),"chains":len(r.get("chain_results",[])),"solve_trace":len(r.get("solve_trace",[]))} for r in reports],key=lambda x:(x["flags"],x["answers"],x["artifacts"],x["chains"],x["solve_trace"]),reverse=True)[:180]
    summary={"flags":flags,"weak_flag_candidates":weak,"answer_candidates":answers,"flag_wrapping_helpers":wrappers,"evidence_scored_candidates":evscored,"autopilot_reviews":reviews,"agent_trace":traces,"solve_trace":solve_traces,"verified_flags":verified_all,"exact_flags":exact,"kinds":kinds,"evidence_board":evidence,"top_findings":evidence,"top_chains":chains,"agents":sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:160],"transformations":sorted(transforms,key=lambda x:x.get("score",0),reverse=True)[:360],"artifacts":artifacts,"recipes":recipes,"artifact_graphs":graphs[:160],"verifyloops":verifyloops[:160],"hypotheses":workflowbrain_project_hypotheses(reports) if "workflowbrain_project_hypotheses" in globals() else [],"workflow_steps":sorted(workflow+actions,key=lambda x:x.get("priority",0),reverse=True)[:200],"missing_tools":sorted(set(missing))[:160],"priority_files":priority}
    summary["health"]=cl_project_health(reports, summary) if "cl_project_health" in globals() else {"status":"solved" if flags else ("weak_flags" if weak else ("answer_candidates" if answers else "needs_review"))}
    summary["unresolved_plan"]=cl_unresolved_plan(reports) if "cl_unresolved_plan" in globals() else []
    return summary
def wf_scan_numeric_tables(data, root, report):
    """Static table agent: scan doubles/ints for coeff*i -> little-endian ASCII.
    v36 fix: scan all 0..7 alignments, not only file offsets divisible by 8.
    """
    arts=[]; chains=[]
    data=bytes(data or b"")
    candidates=[]
    max_bytes=min(len(data), 6_000_000)
    # Double windows across all alignments.
    for align in range(8):
        for off in range(align, max_bytes-8*6, 8):
            if off > 1_500_000 and off % 64 != align:
                continue
            vals=[]; ok=True
            for j in range(1, 25):
                pos=off+(j-1)*8
                if pos+8>max_bytes: break
                try:
                    d=struct.unpack("<d", data[pos:pos+8])[0]
                except Exception:
                    ok=False; break
                if not math.isfinite(d) or abs(d)>1e9:
                    ok=False; break
                vals.append(d)
            if len(vals)<6 or not ok:
                continue
            for n in range(6, min(24,len(vals))+1):
                products=[int(vals[i-1]*i) & 0xffff for i in range(1,n+1)]
                for endian in ["little","big"]:
                    txt=wf_extract_ascii_from_u16(products,endian)
                    # Strip trailing null/control-ish endings for score, but keep raw artifact.
                    clean="".join(ch for ch in txt if 32<=ord(ch)<127)
                    sc=max(wf_ascii_quality(txt), wf_ascii_quality(clean))
                    # Extra boost for leet flag body pattern with underscores.
                    if re.fullmatch(r"[A-Za-z0-9_\-:.+]{8,120}", clean) and "_" in clean:
                        sc+=80
                    if sc>=115 or vf_primary_flags(txt,limit=2) or vf_primary_flags(clean,limit=2):
                        candidates.append({"offset":off,"alignment":align,"count":n,"method":f"double_coeff_times_index_{endian}","text":clean or txt,"raw_text":txt,"score":sc,"values":products})
                        break
    # Raw u16 arrays as fallback.
    for align in range(2):
        for off in range(align, min(max_bytes,2_000_000)-2*8, 2):
            if off>300000 and off%32!=align:
                continue
            vals=[]
            for j in range(0,40):
                pos=off+j*2
                if pos+2>max_bytes: break
                vals.append(int.from_bytes(data[pos:pos+2],"little"))
            if len(vals)>=8:
                for endian in ["little","big"]:
                    txt=wf_extract_ascii_from_u16(vals[:24],endian)
                    clean="".join(ch for ch in txt if 32<=ord(ch)<127)
                    sc=max(wf_ascii_quality(txt),wf_ascii_quality(clean))
                    if re.fullmatch(r"[A-Za-z0-9_\-:.+]{8,120}", clean) and "_" in clean:
                        sc+=60
                    if sc>=140 or vf_primary_flags(txt,limit=2):
                        candidates.append({"offset":off,"alignment":align,"count":24,"method":f"u16_{endian}_ascii_pairs","text":clean or txt,"raw_text":txt,"score":sc,"values":vals[:24]})
                        break
    out=[]; seen=set()
    for c in sorted(candidates,key=lambda x:x.get("score",0),reverse=True):
        key=(c["method"],c["text"][:100])
        if key not in seen:
            seen.add(key); out.append(c)
    out=out[:80]
    if out:
        art=wf_solution_art(root,report,"numeric_table_candidates.json",json.dumps(out,indent=2,ensure_ascii=False),"writeupforge_numeric_table_candidates",180,"Numeric table/static coefficient hidden ASCII candidates")
        if art: arts.append(art)
        for c in out[:20]:
            text=(c.get("text") or "").strip()
            flags=vf_primary_flags(text,limit=5)
            if flags:
                for f in flags:
                    if f not in report.setdefault("flags",[]): report["flags"].append(f)
                    wf_add_solve_trace(report,"NumericTableAgent flag",f"{f} from {c['method']} offset {c['offset']}",260,art.get("path") if art else "",f)
            elif re.fullmatch(r"[A-Za-z0-9_\-:.+]{8,120}", text):
                report.setdefault("answer_candidates",[]).append({"value":text,"source":"NumericTableAgent:"+c["method"],"why":"Numeric table decoded to flag-body-like ASCII; consider wrapping if challenge expects ctf_cs{...}.","score":230})
                report.setdefault("flag_wrapping_helpers",[]).append({"answer":text,"suggested_flag":f"ctf_cs{{{text}}}","source":"NumericTableAgent","score":225,"why":"WriteupForge numeric table produced a likely flag body."})
                wf_add_solve_trace(report,"NumericTableAgent flag body",f"{text} from {c['method']} offset {c['offset']}; suggested ctf_cs{{{text}}}",230,art.get("path") if art else "",f"ctf_cs{{{text}}}")
            chains.append({"type":"writeupforge_numeric_table","input":c["method"],"output":text,"flags":flags,"score":c.get("score",0)+120,"chain_source":f"NumericTableAgent offset={c.get('offset')}"})
    if chains:
        af_add_chain(report,chains,60)
        wf_add_solve_trace(report,"NumericTableAgent",f"{len(out)} numeric table candidates; {len(chains)} chain items",180)
    return arts
def wf_numeric_candidate_score(txt):
    s="".join(ch for ch in str(txt or "") if 32<=ord(ch)<127)
    if len(s)<8:
        return 0
    score=0
    printable=len(s)/max(1,len(str(txt)))
    score+=int(printable*60)
    low=s.lower()
    if "ctf_cs{" in low: score+=300
    if re.fullmatch(r"[A-Za-z0-9_\-:.+]{8,140}",s): score+=60
    if "_" in s: score+=45
    if re.search(r"[a-z][0-9][a-z]|[0-9][a-z][0-9]",low): score+=25
    if any(k in low for k in ["flag","secret","key","leak","num","instability"]): score+=35
    if len(s)>=16: score+=30
    if len(s)>160: score-=40
    return score
def wf_scan_numeric_tables(data, root, report):
    """Robust static table agent for writeup-style numeric hiding."""
    arts=[]; chains=[]
    data=bytes(data or b"")
    max_bytes=min(len(data), 5_000_000)
    candidates=[]
    # Scan every byte alignment for double arrays; stride every byte for first MB, then sparser.
    offsets=list(range(0, min(max_bytes, 1_000_000)-8*6))
    if max_bytes>1_000_000:
        offsets += list(range(1_000_000, max_bytes-8*6, 8))
    for off in offsets:
        vals=[]
        ok=True
        for j in range(24):
            pos=off+j*8
            if pos+8>max_bytes: break
            try:
                d=struct.unpack("<d", data[pos:pos+8])[0]
            except Exception:
                ok=False; break
            if not math.isfinite(d) or abs(d)>1e10:
                ok=False; break
            vals.append(d)
        if not ok or len(vals)<6:
            continue
        for n in range(6, min(24,len(vals))+1):
            # coeff[i] * i, using 1-based index inside the discovered table.
            products=[int(round(vals[i-1]*i)) & 0xffff for i in range(1,n+1)]
            for endian in ["little","big"]:
                raw=wf_extract_ascii_from_u16(products,endian)
                clean="".join(ch for ch in raw if 32<=ord(ch)<127)
                sc=wf_numeric_candidate_score(clean)
                # Require a strong structured text clue, not merely printable bytes.
                if sc>=150:
                    candidates.append({"offset":off,"count":n,"method":f"double_coeff_times_index_{endian}","text":clean,"raw_text":raw,"score":sc,"values":products})
    # Also try raw 16-bit words.
    for off in range(0, min(max_bytes, 800000)-2*8, 2):
        vals=[int.from_bytes(data[off+j*2:off+j*2+2],"little") for j in range(0, min(40,(max_bytes-off)//2))]
        for n in range(8, min(32,len(vals))+1):
            for endian in ["little","big"]:
                raw=wf_extract_ascii_from_u16(vals[:n],endian)
                clean="".join(ch for ch in raw if 32<=ord(ch)<127)
                sc=wf_numeric_candidate_score(clean)
                if sc>=170:
                    candidates.append({"offset":off,"count":n,"method":f"u16_{endian}_ascii_pairs","text":clean,"raw_text":raw,"score":sc,"values":vals[:n]})
    # Prefer longer, higher-score candidates.
    out=[]; seen=set()
    for c in sorted(candidates,key=lambda x:(x.get("score",0),len(x.get("text",""))),reverse=True):
        text=c.get("text","")
        # Avoid tiny substrings if a longer candidate starts with it.
        if any(text and other.get("text","").startswith(text) and len(other.get("text",""))>len(text)+4 for other in out[:20]):
            continue
        key=(c["method"],text[:160])
        if key not in seen:
            seen.add(key); out.append(c)
    out=out[:80]
    if not out:
        return []
    art=wf_solution_art(root,report,"numeric_table_candidates.json",json.dumps(out,indent=2,ensure_ascii=False),"writeupforge_numeric_table_candidates",190,"Numeric table/static coefficient hidden ASCII candidates")
    if art: arts.append(art)
    for c in out[:25]:
        text=(c.get("text") or "").strip()
        flags=vf_primary_flags(text,limit=5)
        if flags:
            for f in flags:
                if f not in report.setdefault("flags",[]): report["flags"].append(f)
                wf_add_solve_trace(report,"NumericTableAgent flag",f"{f} from {c['method']} offset {c['offset']}",280,art.get("path") if art else "",f)
        elif re.fullmatch(r"[A-Za-z0-9_\-:.+]{8,140}", text):
            report.setdefault("answer_candidates",[]).append({"value":text,"source":"NumericTableAgent:"+c["method"],"why":"Numeric table decoded to flag-body-like ASCII; consider wrapping if challenge expects ctf_cs{...}.","score":245})
            sugg=f"ctf_cs{{{text}}}"
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":text,"suggested_flag":sugg,"source":"NumericTableAgent","score":240,"why":"WriteupForge numeric table produced a likely flag body."})
            wf_add_solve_trace(report,"NumericTableAgent flag body",f"{text} from {c['method']} offset {c['offset']}; suggested {sugg}",245,art.get("path") if art else "",sugg)
        chains.append({"type":"writeupforge_numeric_table","input":c["method"],"output":text,"flags":flags,"score":c.get("score",0)+140,"chain_source":f"NumericTableAgent offset={c.get('offset')}"})
    if chains:
        af_add_chain(report,chains,70)
        wf_add_solve_trace(report,"NumericTableAgent",f"{len(out)} numeric table candidates; {len(chains)} chain items",190,art.get("path") if art else "")
    return arts
def wf_scan_numeric_tables(data, root, report):
    """Final minimal reliable numeric table scanner: detects coeff[i]*i LE/BE ASCII."""
    data=bytes(data or b"")
    max_bytes=min(len(data), 3_000_000)
    found=[]
    # Scan every offset in first 1 MB; then every 8 bytes.
    scan_offsets = range(0, min(max_bytes, 1_000_000)-8*6)
    for off in scan_offsets:
        vals=[]
        good=True
        for j in range(24):
            pos=off+j*8
            if pos+8>max_bytes: break
            try:
                d=struct.unpack("<d", data[pos:pos+8])[0]
            except Exception:
                good=False; break
            if not math.isfinite(d) or abs(d)>1e10:
                good=False; break
            vals.append(d)
        if not good or len(vals)<6:
            continue
        best_for_offset=None
        for n in range(6, min(24,len(vals))+1):
            nums=[int(round(vals[i-1]*i)) & 0xffff for i in range(1,n+1)]
            for endian in ("little","big"):
                txt=wf_extract_ascii_from_u16(nums,endian)
                clean="".join(ch for ch in txt if 32<=ord(ch)<127)
                score=wf_numeric_candidate_score(clean)
                if score>=150:
                    cand={"offset":off,"count":n,"method":f"double_coeff_times_index_{endian}","text":clean,"score":score,"values":nums}
                    if best_for_offset is None or (cand["score"],len(cand["text"]))>(best_for_offset["score"],len(best_for_offset["text"])):
                        best_for_offset=cand
        if best_for_offset:
            found.append(best_for_offset)
    # Raw u16 fallback only if no double candidates.
    if not found:
        for off in range(0, min(max_bytes,500000)-16, 2):
            vals=[int.from_bytes(data[off+j*2:off+j*2+2],"little") for j in range(32) if off+j*2+2<=max_bytes]
            for endian in ("little","big"):
                txt=wf_extract_ascii_from_u16(vals,endian)
                clean="".join(ch for ch in txt if 32<=ord(ch)<127)
                score=wf_numeric_candidate_score(clean)
                if score>=170:
                    found.append({"offset":off,"count":len(vals),"method":f"u16_{endian}_ascii_pairs","text":clean,"score":score,"values":vals})
                    break
    # Dedupe, prefer longest/highest.
    out=[]; seen=set()
    for c in sorted(found,key=lambda x:(x["score"],len(x["text"])) ,reverse=True):
        text=c["text"].strip()
        if not text: continue
        if any(text in o["text"] and len(o["text"])>=len(text) for o in out[:20]):
            continue
        key=text.lower()
        if key not in seen:
            seen.add(key); out.append(c)
        if len(out)>=40: break
    if not out:
        return []
    arts=[]
    art=wf_solution_art(root,report,"numeric_table_candidates.json",json.dumps(out,indent=2,ensure_ascii=False),"writeupforge_numeric_table_candidates",190,"Numeric table/static coefficient hidden ASCII candidates")
    if art: arts.append(art)
    chains=[]
    for c in out[:20]:
        text=c["text"].strip()
        flags=vf_primary_flags(text,limit=5)
        if flags:
            for f in flags:
                if f not in report.setdefault("flags",[]): report["flags"].append(f)
                wf_add_solve_trace(report,"NumericTableAgent flag",f"{f} from {c['method']} offset {c['offset']}",280,art.get("path") if art else "",f)
        elif re.fullmatch(r"[A-Za-z0-9_\-:.+]{8,140}", text):
            report.setdefault("answer_candidates",[]).append({"value":text,"source":"NumericTableAgent:"+c["method"],"why":"Numeric table decoded to flag-body-like ASCII; consider wrapping if challenge expects ctf_cs{...}.","score":245})
            sugg=f"ctf_cs{{{text}}}"
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":text,"suggested_flag":sugg,"source":"NumericTableAgent","score":240,"why":"WriteupForge numeric table produced a likely flag body."})
            wf_add_solve_trace(report,"NumericTableAgent flag body",f"{text} from {c['method']} offset {c['offset']}; suggested {sugg}",245,art.get("path") if art else "",sugg)
        chains.append({"type":"writeupforge_numeric_table","input":c["method"],"output":text,"flags":flags,"score":c["score"]+140,"chain_source":f"NumericTableAgent offset={c['offset']}"})
    af_add_chain(report,chains,70)
    wf_add_solve_trace(report,"NumericTableAgent",f"{len(out)} numeric table candidates; {len(chains)} chain items",190,art.get("path") if art else "")
    return arts
def wf_scan_numeric_tables(data, root, report):
    """Reliable numeric table scanner with local imports: coeff[i]*i -> LE/BE ASCII."""
    import struct as _struct
    import math as _math
    data=bytes(data or b"")
    max_bytes=min(len(data), 3_000_000)
    found=[]
    for off in range(0, min(max_bytes, 1_000_000)-8*6):
        vals=[]; good=True
        for j in range(24):
            pos=off+j*8
            if pos+8>max_bytes: break
            try:
                d=_struct.unpack("<d", data[pos:pos+8])[0]
            except Exception:
                good=False; break
            if not _math.isfinite(d) or abs(d)>1e10:
                good=False; break
            vals.append(d)
        if not good or len(vals)<6:
            continue
        best=None
        for n in range(6, min(24,len(vals))+1):
            nums=[int(round(vals[i-1]*i)) & 0xffff for i in range(1,n+1)]
            for endian in ("little","big"):
                txt=wf_extract_ascii_from_u16(nums,endian)
                clean="".join(ch for ch in txt if 32<=ord(ch)<127)
                score=wf_numeric_candidate_score(clean)
                if score>=150:
                    cand={"offset":off,"count":n,"method":f"double_coeff_times_index_{endian}","text":clean,"score":score,"values":nums}
                    if best is None or (cand["score"],len(cand["text"]))>(best["score"],len(best["text"])):
                        best=cand
        if best:
            found.append(best)
    if not found:
        for off in range(0, min(max_bytes,500000)-16, 2):
            vals=[int.from_bytes(data[off+j*2:off+j*2+2],"little") for j in range(32) if off+j*2+2<=max_bytes]
            for endian in ("little","big"):
                txt=wf_extract_ascii_from_u16(vals,endian)
                clean="".join(ch for ch in txt if 32<=ord(ch)<127)
                score=wf_numeric_candidate_score(clean)
                if score>=170:
                    found.append({"offset":off,"count":len(vals),"method":f"u16_{endian}_ascii_pairs","text":clean,"score":score,"values":vals})
                    break
    out=[]; seen=set()
    for c in sorted(found,key=lambda x:(x["score"],len(x["text"])) ,reverse=True):
        text=c["text"].strip()
        if not text: continue
        if any(text in o["text"] and len(o["text"])>=len(text) for o in out[:20]):
            continue
        key=text.lower()
        if key not in seen:
            seen.add(key); out.append(c)
        if len(out)>=40: break
    if not out:
        return []
    arts=[]
    art=wf_solution_art(root,report,"numeric_table_candidates.json",json.dumps(out,indent=2,ensure_ascii=False),"writeupforge_numeric_table_candidates",190,"Numeric table/static coefficient hidden ASCII candidates")
    if art: arts.append(art)
    chains=[]
    for c in out[:20]:
        text=c["text"].strip()
        flags=vf_primary_flags(text,limit=5)
        if flags:
            for f in flags:
                if f not in report.setdefault("flags",[]): report["flags"].append(f)
                wf_add_solve_trace(report,"NumericTableAgent flag",f"{f} from {c['method']} offset {c['offset']}",280,art.get("path") if art else "",f)
        elif re.fullmatch(r"[A-Za-z0-9_\-:.+]{8,140}", text):
            report.setdefault("answer_candidates",[]).append({"value":text,"source":"NumericTableAgent:"+c["method"],"why":"Numeric table decoded to flag-body-like ASCII; consider wrapping if challenge expects ctf_cs{...}.","score":245})
            sugg=f"ctf_cs{{{text}}}"
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":text,"suggested_flag":sugg,"source":"NumericTableAgent","score":240,"why":"WriteupForge numeric table produced a likely flag body."})
            wf_add_solve_trace(report,"NumericTableAgent flag body",f"{text} from {c['method']} offset {c['offset']}; suggested {sugg}",245,art.get("path") if art else "",sugg)
        chains.append({"type":"writeupforge_numeric_table","input":c["method"],"output":text,"flags":flags,"score":c["score"]+140,"chain_source":f"NumericTableAgent offset={c['offset']}"})
    af_add_chain(report,chains,70)
    wf_add_solve_trace(report,"NumericTableAgent",f"{len(out)} numeric table candidates; {len(chains)} chain items",190,art.get("path") if art else "")
    return arts
def project_summary(reports, meta):
    flags=[]; weak=[]; verified_map={}; kinds={}; evidence=[]; chains=[]; actions=[]; missing=[]; agents=[]; transforms=[]; verifyloops=[]; artifacts=[]; recipes=[]; graphs=[]; answers=[]; wrappers=[]; reviews=[]; traces=[]; evscored=[]; solve_traces=[]
    for r in reports:
        kinds[r.get("kind","?")]=kinds.get(r.get("kind","?"),0)+1
        for tr in r.get("solve_trace",[])[:220]: solve_traces.append({"file":r.get("rel"),**tr})
        for tr in r.get("agent_trace",[])[:160]: traces.append({"file":r.get("rel"),**tr})
        for wf in r.get("weak_flag_candidates",[])[:60]: weak.append({"file":r.get("rel"),**wf})
        for ev in r.get("evidence_scored_candidates",[])[:100]: evscored.append({"file":r.get("rel"),**ev})
        for v in r.get("verified_flags_visible",[])[:100]:
            key=(v.get("flag") or "").lower(); vv={"file":r.get("rel"),**v}
            if key and (key not in verified_map or vv.get("score",0)>verified_map[key].get("score",0)): verified_map[key]=vv
        for f in r.get("flags",[])[:120]:
            if smartsolve_strict_target_flag_ok(f): flags.append({"file":r.get("rel"),"flag":f,"score":999,"status":"promoted_with_evidence"})
        for ans in r.get("answer_candidates",[])[:160]: answers.append({"file":r.get("rel"),**ans})
        for h in r.get("flag_wrapping_helpers",[])[:100]: wrappers.append({"file":r.get("rel"),**h})
        for f in r.get("findings",[])[:80]:
            if not is_noisy_candidate_text(f.get("value",""),f.get("why",""),f.get("type","")): evidence.append({"file":r.get("rel"),**f})
        for c in r.get("chain_results",[])[:80]:
            out=(c.get("output","") or "")[:900]
            if c.get("score",0)>70 and not is_noisy_candidate_text(out,c.get("type",""),"chain"):
                chains.append({"file":r.get("rel"),"type":c.get("type"),"source":c.get("chain_source"),"score":c.get("score"),"output":out})
        for s in r.get("next_steps",[])[:10]: actions.append({"file":r.get("rel"),**s})
        for a in r.get("agent_runs",[])[:10]: agents.append({"file":r.get("rel"),"kind":r.get("kind"),**a})
        for t in r.get("transformations",[])[:140]: transforms.append({"file":r.get("rel"),**t})
        if r.get("verifyloop"): verifyloops.append({"file":r.get("rel"),"kind":r.get("kind"),**r.get("verifyloop",{})})
        # important: preserve all high-priority WriteupForge/AgentForge artifacts
        for art in r.get("artifacts",[])[:700]:
            a=dict(art)
            a.setdefault("file",r.get("rel"))
            artifacts.append(a)
        for rec in r.get("recipe_runs",[])[:12]: recipes.append({"file":r.get("rel"),"kind":r.get("kind"),**rec})
        if r.get("artifact_graph"): graphs.append({"file":r.get("rel"),"graph":r.get("artifact_graph")})
        for o in r.get("outputs",[])[:100]:
            if not o.get("ok") and "not installed" in (o.get("out","").lower()): missing.append((o.get("out","").split() or ["unknown"])[0])
    def dedupe_by(items,keyfn,scorefn=lambda x:x.get("score",0)):
        mp={}
        for x in items:
            k=keyfn(x)
            if k and (k not in mp or scorefn(x)>scorefn(mp[k])): mp[k]=x
        return list(mp.values())
    flags=sorted(dedupe_by(flags,lambda x:(x.get("flag") or "").lower()),key=lambda x:x.get("score",0),reverse=True)[:120]
    weak=sorted(dedupe_by(weak,lambda x:(x.get("flag") or "").lower(), lambda x:x.get("support",0)), key=lambda x:x.get("support",0), reverse=True)[:160]
    answers=sorted(dedupe_by(answers,lambda x:(x.get("value") or "").lower()),key=lambda x:x.get("score",0),reverse=True)[:320]
    wrappers=sorted(dedupe_by(wrappers,lambda x:(x.get("suggested_flag") or "").lower()),key=lambda x:x.get("score",0),reverse=True)[:180]
    evscored=sorted(dedupe_by(evscored,lambda x:(x.get("value") or "").lower(), lambda x:x.get("evidence_score",0)), key=lambda x:x.get("evidence_score",0), reverse=True)[:220]
    verified_all=sorted(verified_map.values(),key=lambda x:x.get("score",0),reverse=True)[:120]
    def art_priority(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "writeupforge" in txt: s+=500
        if "numeric" in txt or "piet" in txt or "tile" in txt or "lsb" in txt: s+=250
        if "agentforge" in txt: s+=120
        return (bool(a.get("exists",False)), s, int(a.get("size",0) or 0))
    artifacts=sorted(dedupe_by(artifacts,lambda x:x.get("path") or x.get("url") or x.get("name"), lambda x:art_priority(x)[1]),key=art_priority,reverse=True)[:1600]
    evidence=sorted(evidence,key=lambda x:x.get("score",0),reverse=True)[:180]
    chains=sorted(chains,key=lambda x:x.get("score",0) or 0,reverse=True)[:180]
    recipes=sorted(recipes,key=lambda x:x.get("score",0),reverse=True)[:200]
    exact=[f for f in flags if "ctf_cs{" in f.get("flag","").lower()]
    workflow=[]
    if exact: workflow.append({"priority":100,"step":"Submit/check top strict ctf_cs flag with solve evidence.","why":"Flag has chain/artifact/trace support."})
    elif weak: workflow.append({"priority":98,"step":"Inspect Weak Flag Candidates, but do not trust them yet.","why":"They look like flags but lack enough solve evidence."})
    elif answers: workflow.append({"priority":97,"step":"Open Answer Candidates and Flag Wrapping Helpers.","why":"No strict flag found; likely answer may need wrapping as ctf_cs{answer}."})
    if solve_traces: workflow.append({"priority":96,"step":"Open Solve Trace.","why":"WriteupForge shows the multi-step reasoning path and created artifacts."})
    if evscored: workflow.append({"priority":95,"step":"Open Evidence Scores.","why":"Candidates are ranked by supporting sources."})
    priority=sorted([{"file":r.get("rel"),"kind":r.get("kind"),"flags":len(r.get("flags",[])),"weak_flags":len(r.get("weak_flag_candidates",[])),"answers":len(r.get("answer_candidates",[])),"wrappers":len(r.get("flag_wrapping_helpers",[])),"artifacts":len(r.get("artifacts",[])),"chains":len(r.get("chain_results",[])),"solve_trace":len(r.get("solve_trace",[]))} for r in reports],key=lambda x:(x["flags"],x["answers"],x["artifacts"],x["chains"],x["solve_trace"]),reverse=True)[:200]
    summary={"flags":flags,"weak_flag_candidates":weak,"answer_candidates":answers,"flag_wrapping_helpers":wrappers,"evidence_scored_candidates":evscored,"autopilot_reviews":reviews,"agent_trace":traces,"solve_trace":solve_traces,"verified_flags":verified_all,"exact_flags":exact,"kinds":kinds,"evidence_board":evidence,"top_findings":evidence,"top_chains":chains,"agents":sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:180],"transformations":sorted(transforms,key=lambda x:x.get("score",0),reverse=True)[:420],"artifacts":artifacts,"recipes":recipes,"artifact_graphs":graphs[:180],"verifyloops":verifyloops[:180],"hypotheses":workflowbrain_project_hypotheses(reports) if "workflowbrain_project_hypotheses" in globals() else [],"workflow_steps":sorted(workflow+actions,key=lambda x:x.get("priority",0),reverse=True)[:220],"missing_tools":sorted(set(missing))[:180],"priority_files":priority}
    summary["health"]=cl_project_health(reports, summary) if "cl_project_health" in globals() else {"status":"solved" if flags else ("weak_flags" if weak else ("answer_candidates" if answers else "needs_review"))}
    summary["unresolved_plan"]=cl_unresolved_plan(reports) if "cl_unresolved_plan" in globals() else []
    return summary
def wf_scan_numeric_tables(data, root, report):
    """Fast reliable numeric scanner: all 8 double alignments, 8-byte stride."""
    import struct as _struct
    import math as _math
    data=bytes(data or b"")
    max_bytes=min(len(data), 5_000_000)
    found=[]
    for align in range(8):
        for off in range(align, min(max_bytes, 2_000_000)-8*6, 8):
            vals=[]; good=True
            for j in range(24):
                pos=off+j*8
                if pos+8>max_bytes: break
                try:
                    d=_struct.unpack("<d", data[pos:pos+8])[0]
                except Exception:
                    good=False; break
                if not _math.isfinite(d) or abs(d)>1e10:
                    good=False; break
                vals.append(d)
            if not good or len(vals)<6:
                continue
            best=None
            for n in range(6, min(24,len(vals))+1):
                nums=[int(round(vals[i-1]*i)) & 0xffff for i in range(1,n+1)]
                for endian in ("little","big"):
                    txt=wf_extract_ascii_from_u16(nums,endian)
                    clean="".join(ch for ch in txt if 32<=ord(ch)<127)
                    score=wf_numeric_candidate_score(clean)
                    if score>=150:
                        cand={"offset":off,"alignment":align,"count":n,"method":f"double_coeff_times_index_{endian}","text":clean,"score":score,"values":nums}
                        if best is None or (cand["score"],len(cand["text"]))>(best["score"],len(best["text"])):
                            best=cand
            if best:
                found.append(best)
    if not found:
        for align in range(2):
            for off in range(align, min(max_bytes,800000)-16, 2):
                vals=[int.from_bytes(data[off+j*2:off+j*2+2],"little") for j in range(32) if off+j*2+2<=max_bytes]
                for endian in ("little","big"):
                    txt=wf_extract_ascii_from_u16(vals,endian)
                    clean="".join(ch for ch in txt if 32<=ord(ch)<127)
                    score=wf_numeric_candidate_score(clean)
                    if score>=170:
                        found.append({"offset":off,"alignment":align,"count":len(vals),"method":f"u16_{endian}_ascii_pairs","text":clean,"score":score,"values":vals})
                        break
    out=[]; seen=set()
    for c in sorted(found,key=lambda x:(x["score"],len(x["text"])) ,reverse=True):
        text=c["text"].strip()
        if not text: continue
        if any(text in o["text"] and len(o["text"])>=len(text) for o in out[:20]):
            continue
        key=text.lower()
        if key not in seen:
            seen.add(key); out.append(c)
        if len(out)>=40: break
    if not out:
        return []
    arts=[]
    art=wf_solution_art(root,report,"numeric_table_candidates.json",json.dumps(out,indent=2,ensure_ascii=False),"writeupforge_numeric_table_candidates",190,"Numeric table/static coefficient hidden ASCII candidates")
    if art: arts.append(art)
    chains=[]
    for c in out[:20]:
        text=c["text"].strip()
        flags=vf_primary_flags(text,limit=5)
        if flags:
            for f in flags:
                if f not in report.setdefault("flags",[]): report["flags"].append(f)
                wf_add_solve_trace(report,"NumericTableAgent flag",f"{f} from {c['method']} offset {c['offset']}",280,art.get("path") if art else "",f)
        elif re.fullmatch(r"[A-Za-z0-9_\-:.+]{8,140}", text):
            report.setdefault("answer_candidates",[]).append({"value":text,"source":"NumericTableAgent:"+c["method"],"why":"Numeric table decoded to flag-body-like ASCII; consider wrapping if challenge expects ctf_cs{...}.","score":245})
            sugg=f"ctf_cs{{{text}}}"
            report.setdefault("flag_wrapping_helpers",[]).append({"answer":text,"suggested_flag":sugg,"source":"NumericTableAgent","score":240,"why":"WriteupForge numeric table produced a likely flag body."})
            wf_add_solve_trace(report,"NumericTableAgent flag body",f"{text} from {c['method']} offset {c['offset']}; suggested {sugg}",245,art.get("path") if art else "",sugg)
        chains.append({"type":"writeupforge_numeric_table","input":c["method"],"output":text,"flags":flags,"score":c["score"]+140,"chain_source":f"NumericTableAgent offset={c['offset']}"})
    af_add_chain(report,chains,70)
    wf_add_solve_trace(report,"NumericTableAgent",f"{len(out)} numeric table candidates; {len(chains)} chain items",190,art.get("path") if art else "")
    return arts
def smartsolve_strict_target_flag_ok(flag, meta=None):
    flag=str(flag or "").strip()
    if not STRICT_PRIMARY_FLAG_RE.fullmatch(flag):
        return False
    inner=flag_inner(flag)
    low=inner.lower().strip()
    norm=low.replace(".", "_").replace("-", "_")
    if low in PLACEHOLDER_INNERS:
        return False
    if any(x in norm for x in ["placeholder","your_flag","not_the_flag","notflag","insert_flag","change_me"]):
        return False
    if any(w in norm for w in LT_TEMPLATE_WORDS):
        return False
    if len(inner)>120:
        return False
    # Stronger against accidental decoder garbage:
    # short one-token mixed strings like ctf_cs{iJqI8tf} are almost always false positives.
    if len(inner)<10 and "_" not in inner and "-" not in inner and "." not in inner:
        return False
    if len(inner)<6:
        return False
    if any(ord(c)<32 or ord(c)>126 for c in inner):
        return False
    if "ctf_cs" in low:
        return False
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_\-:.+]{5,120}", inner):
        return False
    # If it is mixed-case only with very little structure, require length or separators.
    if len(inner)<14 and "_" not in inner and "-" not in inner and "." not in inner and not any(ch in inner for ch in ":+"):
        # allow readable lowercase-ish words with digits, reject high-entropy mixed-case fragments.
        if re.search(r"[A-Z]",inner) and re.search(r"[a-z]",inner):
            return False
    return True
def vf_primary_flags(text, limit=80, scan_limit=50000):
    text=str(text or "")[:scan_limit]
    hits=[]; seen=set()
    for m in STRICT_PRIMARY_FLAG_RE.finditer(text):
        cand=m.group(0)
        if smartsolve_strict_target_flag_ok(cand):
            k=cand.lower()
            if k not in seen:
                seen.add(k); hits.append(cand)
                if len(hits)>=limit: break
    return hits
ALT_FLAG_RE = re.compile(r"\b(?:gigem|flag|uiuctf|ictf|picoctf|utflag|tamuctf)\{[^{}\r\n]{4,160}\}", re.I)
def msf_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        wf_add_solve_trace(report, "MultiStepForge:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({"stage":"MultiStepForge:"+str(stage),"detail":str(detail)[:800],"confidence":int(confidence or 0),"artifact":artifact or "","flag":flag or ""})
def msf_art(root, report, name, content, kind="multistepforge_artifact", score=100, note=""):
    outdir=root/"generated"/"multistepforge"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"MultiStepForge","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        msf_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        msf_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def msf_alt_flags(text, limit=80):
    out=[]; seen=set()
    for m in ALT_FLAG_RE.finditer(str(text or "")[:200000]):
        f=m.group(0)
        k=f.lower()
        if k not in seen:
            seen.add(k); out.append(f)
            if len(out)>=limit: break
    return out
def vf_collect_answer_candidates(report):
    # v37 override: include alternate CTF flag formats as answer candidates, not promoted ctf_cs flags.
    cands=[]
    for f in report.get("flags",[])[:120]:
        vf_add_answer(cands,f,"promoted flag","strict ctf_cs candidate",260)
    for v in report.get("verified_flags",[])[:100]:
        vf_add_answer(cands,v.get("flag",""),"verified_flags","; ".join(v.get("reasons",[])[:3]),int(v.get("score",0)//4))
    statement=ff_statement_text(report) if "ff_statement_text" in globals() else ""
    joined=statement+"\n"+"\n".join(report.get("strings",[])[:1600])+"\n"+"\n".join((o.get("out") or "")[:8000] for o in report.get("outputs",[])[:120])
    joined+="\n"+"\n".join((c.get("output") or "")[:8000] for c in report.get("chain_results",[])[:140])
    for alt in msf_alt_flags(joined,limit=80):
        cands.append({"value":alt,"source":"alternate_ctf_flag_format","why":"Known non-primary CTF flag format; kept as candidate because target contest may require ctf_cs only.","score":235})
    for alt in vf_alt_ctf_candidates(joined,limit=25):
        cands.append({"value":alt,"source":"alternate_ctf_like","why":"Not promoted because only strict ctf_cs{...} is primary.","score":90})
    markers=["answer","atsakymas","ats","raktas","key","secret","slapta","slaptažodis","slaptazodis","password","pass","code","kodas","token","login","vartotojas","user","username","flag"]
    for line in joined.splitlines()[:4000]:
        line=line.strip(); low=line.lower()
        if not (3<=len(line)<=320): continue
        if any(k in low for k in markers):
            vf_add_answer(cands,line,"statement/strings/chains","answer-like line",55)
            m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|slaptazodis|password|pass|code|kodas|token|login|vartotojas|user|username|flag)\s*[:=]\s*(.+)$",line,re.I)
            if m: vf_add_answer(cands,m.group(1).strip(),"statement/strings/chains","value after marker",105)
    try:
        cands += mb_collect_strong_answers(report)
    except Exception:
        pass
    for c in report.get("chain_results",[])[:160]:
        out=(c.get("output","") or "")[:10000]
        for f in vf_primary_flags(out,limit=10):
            vf_add_answer(cands,f,"chain:"+str(c.get("type","")),"decoded output",int(c.get("score",0)//4)+100)
        for f in msf_alt_flags(out,limit=20):
            cands.append({"value":f,"source":"chain_alt_flag:"+str(c.get("type","")),"why":"Alternate flag format from decoded chain output.","score":230+int(c.get("score",0)//10)})
    for p in report.get("previews",[])[:120]:
        txt=((p.get("ocr","") or "")+"\n"+(p.get("qr","") or "")).strip()
        for f in vf_primary_flags(txt,limit=8):
            vf_add_answer(cands,f,"visual_ocr_qr:"+str(p.get("name","")),"OCR/QR",int(p.get("score",0)//4)+110)
        for f in msf_alt_flags(txt,limit=10):
            cands.append({"value":f,"source":"visual_alt_flag:"+str(p.get("name","")),"why":"Alternate flag format in OCR/QR.","score":230})
        for line in txt.splitlines()[:45]:
            line=line.strip()
            if 3<=len(line)<=180:
                vf_add_answer(cands,line,"visual_ocr:"+str(p.get("name","")),"OCR text",int(p.get("score",0)//8)+30)
    for a in report.get("artifacts",[])[:220]:
        p=Path(a.get("path",""))
        try:
            if not p.exists() or not p.is_file() or p.stat().st_size>=900000: continue
            if not (p.suffix.lower() in [".txt",".json",".log",".md",".csv",".xml",".svg"] or any(x in p.name.lower() for x in ["ocr","decoded","answer","secret","key","brief","strings","fallback","constants","chain","decompressed","timestamp","spectrogram","qr","hadamard"])):
                continue
            txt=p.read_text(encoding="utf-8",errors="ignore")[:20000]
            for f in vf_primary_flags(txt,limit=8):
                vf_add_answer(cands,f,"artifact:"+a.get("kind",""),"artifact text",int(a.get("score",0)//3)+105)
            for f in msf_alt_flags(txt,limit=20):
                cands.append({"value":f,"source":"artifact_alt_flag:"+a.get("kind",""),"why":"Alternate flag format in artifact text.","score":235+int(a.get("score",0)//10)})
            for line in txt.splitlines()[:150]:
                line=line.strip(); low=line.lower()
                if 3<=len(line)<=240 and any(k in low for k in markers):
                    vf_add_answer(cands,line,"artifact_context:"+a.get("kind",""),"answer-like artifact line",int(a.get("score",0)//5)+45)
                    m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|slaptazodis|password|pass|code|kodas|token|login|vartotojas|user|username|flag)\s*[:=]\s*(.+)$",line,re.I)
                    if m: vf_add_answer(cands,m.group(1).strip(),"artifact_value:"+a.get("kind",""),"value after marker",int(a.get("score",0)//5)+90)
        except Exception:
            pass
    out=[]; seen=set()
    for x in sorted(cands,key=lambda z:z.get("score",0),reverse=True):
        val=x.get("value","").strip()
        k=val.lower()
        if k and k not in seen and not ("ctf_cs{vietos" in k):
            seen.add(k); out.append(x)
    return out[:320]
def msf_learn_repo_context(report, root, data, text):
    """Read README/solve/source clues in challenge folders and convert them to solve hints."""
    p=Path(report.get("path",""))
    clues=[]
    # Current file text clues
    for pat, name in [
        (r"walsh|hadamard|fwht|ifwht", "Walsh-Hadamard transform"),
        (r"stft|short term fourier|complex64|n_fft|hop_length", "STFT inverse audio"),
        (r"tinymt|mt19937|mersenne|prng|rng_state|xorshift", "PRNG state/linear recovery"),
        (r"onnx|gradient|genetic|model|local maximum", "ML model optimization"),
        (r"piet|npiet|codel", "Piet image program"),
        (r"zstd|zstandard|sb3|scratch", "zstd/Scratch archive"),
        (r"tcache|heap|rop|ret2libc|one_gadget|shellcode", "pwn exploit path"),
        (r"http3|quic|udp 443|certificate", "HTTP/3/QUIC static web clue"),
        (r"path traversal|directory browsing|convert|avatar|upload|unsanitized", "web traversal/upload clue"),
        (r"timestamp|mtime|minute|second|time capsule", "timestamp hidden data"),
        (r"qr|quick response|checkerboard|timing pattern", "QR checkerboard repair"),
    ]:
        if re.search(pat, text, re.I):
            clues.append(name)
    if clues:
        art=msf_art(root,report,"learned_solve_clues.json",json.dumps({"clues":sorted(set(clues))},indent=2),"multistepforge_learned_clues",135,"Patterns learned from source/readme/solve text")
        msf_trace(report,"PatternLearningAgent",", ".join(sorted(set(clues))),150,art.get("path") if art else "")
    return clues
def msf_timestamp_agent(report, root):
    """Recover hidden text from file mtimes: minute/second values, sorted by name/time."""
    try:
        base=root/"files"
        files=[p for p in base.rglob("*") if p.is_file()]
    except Exception:
        files=[]
    if len(files)<3:
        return []
    rows=[]
    for p in files:
        try:
            st=p.stat()
            import datetime as _dt
            dt=_dt.datetime.fromtimestamp(st.st_mtime)
            rows.append({"path":str(p.relative_to(base)),"mtime":st.st_mtime,"minute":dt.minute,"second":dt.second,"hour":dt.hour,"day":dt.day})
        except Exception:
            pass
    if len(rows)<3:
        return []
    variants={}
    for order_name, ordered in {
        "name": sorted(rows,key=lambda x:x["path"]),
        "mtime": sorted(rows,key=lambda x:x["mtime"]),
        "mtime_desc": sorted(rows,key=lambda x:x["mtime"], reverse=True)
    }.items():
        for field in ["minute","second","hour","day"]:
            vals=[r[field] for r in ordered]
            txt="".join(chr(v) if 32<=v<127 else "." for v in vals)
            variants[f"{order_name}_{field}_ascii"]=txt
        vals=[r["minute"]*60+r["second"] for r in ordered]
        variants[f"{order_name}_minute_second_u16_low_ascii"]="".join(chr(v&255) if 32<=v&255<127 else "." for v in vals)
        variants[f"{order_name}_minute_then_second_ascii"]="".join((chr(r["minute"]) if 32<=r["minute"]<127 else ".")+(chr(r["second"]) if 32<=r["second"]<127 else ".") for r in ordered)
    good={k:v for k,v in variants.items() if wf_ascii_quality(v)>=70 or msf_alt_flags(v) or vf_primary_flags(v)}
    if good:
        art=msf_art(root,report,"timestamp_hidden_data_candidates.json",json.dumps({"rows":rows,"variants":good},indent=2,ensure_ascii=False),"multistepforge_timestamp_candidates",165,"File timestamp minute/second hidden data candidates")
        for v in good.values():
            af_run_text_decoders(report,root,v,"TimestampAgent",500)
        msf_trace(report,"TimestampAgent",f"{len(good)} timestamp variants generated",165,art.get("path") if art else "")
        return [art] if art else []
    return []
def msf_qr_checkerboard_agent(report, root, image_path):
    """Generate QR repair variants: checkerboard XOR/invert/threshold."""
    arts=[]
    try:
        im=Image.open(image_path).convert("L")
        arr=np.array(im)
    except Exception:
        return []
    h,w=arr.shape
    if min(h,w)<80:
        return []
    outdir=root/"generated"/"multistepforge"/safe(report.get("name","image"))/"qr_repair"
    outdir.mkdir(parents=True,exist_ok=True)
    masks={}
    y,x=np.indices((h,w))
    for cell in [1,2,3,4,5,6,8,10]:
        masks[f"checker_cell_{cell}"]=(((x//cell + y//cell)&1)*255).astype("uint8")
    base=(arr>128).astype("uint8")*255
    variants=[]
    for name,mask in masks.items():
        for mode in ["xor","xor_invert"]:
            out=np.bitwise_xor(base,mask)
            if mode=="xor_invert":
                out=255-out
            p=outdir/f"{name}_{mode}.png"
            Image.fromarray(out.astype("uint8")).save(p)
            variants.append(p)
    decoded=[]
    for p in variants:
        if exists("zbarimg"):
            try:
                r=run(["zbarimg","--quiet",str(p)],8)
                if r.get("out","").strip():
                    decoded.append({"image":str(p),"out":r.get("out","").strip()})
                    report.setdefault("outputs",[]).append({"tool":"multistepforge_zbar_qr_repair","ok":r.get("ok"),"cmd":r.get("cmd"),"out":r.get("out")[:20000]})
                    af_run_text_decoders(report,root,r.get("out",""),"QRRepair:"+p.name,500)
            except Exception:
                pass
    contact=outdir/"qr_repair_variants_manifest.json"
    contact.write_text(json.dumps({"variants":[str(p) for p in variants],"decoded":decoded},indent=2),encoding="utf-8")
    art={"kind":"multistepforge_qr_checkerboard_repair","name":contact.name,"path":str(contact),"url":"/api/raw?path="+str(contact),"source":"MultiStepForge","score":150+80*bool(decoded),"note":"Checkerboard XOR/invert QR repair variants; open manifest/images.","exists":True,"size":contact.stat().st_size,"file":report.get("rel","")}
    report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art)
    msf_trace(report,"QRRepairAgent",f"Generated {len(variants)} checkerboard QR variants; decoded={len(decoded)}",art["score"],str(contact))
    return arts
def msf_audio_agent(report, root, path, data, text):
    """Audio/STFT helpers: spectrograms, dominant frequency order, inverse STFT candidates."""
    arts=[]
    p=Path(path)
    suffix=p.suffix.lower()
    if suffix==".wav":
        try:
            import wave as _wave
            import numpy as _np
            with _wave.open(str(p),"rb") as wf:
                sr=wf.getframerate()
                n=wf.getnframes()
                chans=wf.getnchannels()
                raw=wf.readframes(n)
            arr=_np.frombuffer(raw,dtype=_np.int16)
            if chans>1: arr=arr.reshape(-1,chans).mean(axis=1)
            # crude segment dominant frequency trace
            seg=max(256, sr//20)
            freqs=[]
            for start in range(0,len(arr)-seg,seg):
                chunk=arr[start:start+seg].astype("float32")
                spec=np.abs(np.fft.rfft(chunk*np.hanning(len(chunk))))
                f=np.fft.rfftfreq(len(chunk),1/sr)
                mask=(f>500)&(f<12000)
                if mask.any():
                    freqs.append(float(f[mask][int(np.argmax(spec[mask]))]))
            obj={"sample_rate":sr,"frames":n,"channels":chans,"segment_size":seg,"dominant_freqs":freqs[:5000]}
            art=msf_art(root,report,"audio_dominant_frequency_trace.json",json.dumps(obj,indent=2),"multistepforge_audio_freq_trace",145,"Dominant frequency per segment; useful for chopped/sliced audio ordering.")
            if art: arts.append(art)
        except Exception as e:
            msf_trace(report,"AudioAgent failed",str(e),0)
    # STFT numbers text
    if suffix in [".txt",".csv",".dat"] and ("complex" in text.lower() or "stft" in text.lower() or "j" in text[:5000]):
        try:
            # Try parse complex numbers and infer rectangular shape from comments or perfect factors.
            lines=text.splitlines()
            nums=[]
            for line in lines:
                if line.strip().startswith("#"): continue
                for tok in re.findall(r"[-+]?\d+(?:\.\d+)?(?:[-+]\d+(?:\.\d+)?)?j|[-+]?\d+\.\d+(?:e[-+]?\d+)?", line, re.I):
                    try: nums.append(complex(tok.replace("+-","-")))
                    except Exception: pass
                if len(nums)>300000: break
            shape=None
            m=re.search(r"shape:\s*(?:complex\d+\s*)?\(?\s*(\d+)\s*,\s*(\d+)\s*\)?", text, re.I)
            if m: shape=(int(m.group(1)),int(m.group(2)))
            if nums and shape and shape[0]*shape[1]<=len(nums):
                obj={"count":len(nums),"shape":shape,"note":"Parsed STFT-like complex data. Use scipy.signal.istft/librosa to reconstruct audio."}
                art=msf_art(root,report,"stft_parse_hint.json",json.dumps(obj,indent=2),"multistepforge_stft_parse_hint",135,"STFT complex matrix recognized.")
                if art: arts.append(art)
        except Exception as e:
            msf_trace(report,"STFTAgent failed",str(e),0)
    if arts:
        msf_trace(report,"AudioAgent",f"{len(arts)} audio/STFT artifacts",150,arts[0].get("path"))
    return arts
