# Auto-split from sloper_legacy_monolith.py lines 5245-...
def project_summary(reports, meta):
    """Fast aggregation only. Never re-run expensive visual/solver passes here."""
    flags=[]; verified_map={}; kinds={}; evidence=[]; chains=[]; actions=[]; missing=[]; agents=[]; transforms=[]; verifyloops=[]; artifacts=[]; recipes=[]; graphs=[]; answers=[]
    for r in reports:
        kinds[r.get("kind","?")]=kinds.get(r.get("kind","?"),0)+1
        if "answer_candidates" not in r:
            try: r["answer_candidates"]=vf_collect_answer_candidates(r)
            except Exception: r["answer_candidates"]=[]
        for v in r.get("verified_flags_visible",[])[:80]:
            key=(v.get("flag") or "").lower()
            vv={"file":r.get("rel"),**v}
            if key and (key not in verified_map or vv.get("score",0)>verified_map[key].get("score",0)): verified_map[key]=vv
        for f in r.get("flags",[])[:60]:
            if smartsolve_strict_target_flag_ok(f): flags.append({"file":r.get("rel"),"flag":f,"score":999,"status":"promoted"})
        for ans in r.get("answer_candidates",[])[:60]: answers.append({"file":r.get("rel"),**ans})
        for f in r.get("findings",[])[:40]:
            if not is_noisy_candidate_text(f.get("value",""),f.get("why",""),f.get("type","")): evidence.append({"file":r.get("rel"),**f})
        for c in r.get("chain_results",[])[:25]:
            out=(c.get("output","") or "")[:900]
            if c.get("score",0)>70 and not is_noisy_candidate_text(out,c.get("type",""),"chain"):
                chains.append({"file":r.get("rel"),"type":c.get("type"),"source":c.get("chain_source"),"score":c.get("score"),"output":out})
        for s in r.get("next_steps",[])[:8]: actions.append({"file":r.get("rel"),**s})
        for a in r.get("agent_runs",[])[:8]: agents.append({"file":r.get("rel"),"kind":r.get("kind"),**a})
        for t in r.get("transformations",[])[:35]: transforms.append({"file":r.get("rel"),**t})
        if r.get("verifyloop"): verifyloops.append({"file":r.get("rel"),"kind":r.get("kind"),**r.get("verifyloop",{})})
        for art in r.get("artifacts",[])[:180]: artifacts.append(art)
        for rec in r.get("recipe_runs",[])[:10]: recipes.append({"file":r.get("rel"),"kind":r.get("kind"),**rec})
        if r.get("artifact_graph"): graphs.append({"file":r.get("rel"),"graph":r.get("artifact_graph")})
        for o in r.get("outputs",[])[:80]:
            if not o.get("ok") and "not installed" in (o.get("out","").lower()): missing.append((o.get("out","").split() or ["unknown"])[0])
    flag_map={}
    for f in flags:
        key=(f.get("flag") or "").lower()
        if key and (key not in flag_map or f.get("score",0)>flag_map[key].get("score",0)): flag_map[key]=f
    ans_map={}
    for a in answers:
        key=(a.get("value") or "").lower()
        if key and (key not in ans_map or a.get("score",0)>ans_map[key].get("score",0)): ans_map[key]=a
    flags=sorted(flag_map.values(),key=lambda x:x.get("score",0),reverse=True)[:60]
    answers=sorted(ans_map.values(),key=lambda x:x.get("score",0),reverse=True)[:160]
    verified_all=sorted(verified_map.values(),key=lambda x:x.get("score",0),reverse=True)[:80]
    evidence=sorted(evidence,key=lambda x:x.get("score",0),reverse=True)[:100]
    chains=sorted(chains,key=lambda x:x.get("score",0) or 0,reverse=True)[:80]
    artifacts=sorted(artifacts,key=lambda x:(x.get("exists",False),x.get("score",0),x.get("size",0)),reverse=True)[:700]
    recipes=sorted(recipes,key=lambda x:x.get("score",0),reverse=True)[:120]
    exact=[f for f in flags if "ctf_cs{" in f.get("flag","").lower()]
    workflow=[]
    if exact: workflow.append({"priority":100,"step":"Submit/check top strict ctf_cs flag.","why":"Primary contest format candidate survived strict filters."})
    elif answers: workflow.append({"priority":96,"step":"Open Answer Candidates.","why":"No strict flag found; likely answer may be a word/hash/coordinate/key/OCR result."})
    if recipes: workflow.append({"priority":92,"step":"Open Recipes tab and follow top recipe.","why":"Recipe Engine picked likely solve paths."})
    if artifacts: workflow.append({"priority":90,"step":"Open Artifacts / Visual Lab outputs.","why":"Generated/transformed/extracted files are collected with open/copy controls."})
    if evidence: workflow.append({"priority":88,"step":"Open Evidence Board top item.","why":"Noisy candidates are hidden."})
    priority=sorted([{"file":r.get("rel"),"kind":r.get("kind"),"flags":len(r.get("flags",[])),"answers":len(r.get("answer_candidates",[])),"verified":len(r.get("verified_flags_visible",[])),"recipes":len(r.get("recipe_runs",[])),"artifacts":len(r.get("artifacts",[])),"findings":len(r.get("findings",[])),"chains":len(r.get("chain_results",[])),"top_score":max([x.get("score",0) for x in r.get("findings",[])]+[0])} for r in reports],key=lambda x:(x["flags"],x["answers"],x["verified"],x["recipes"],x["top_score"],x["artifacts"]),reverse=True)[:120]
    summary={"flags":flags,"answer_candidates":answers,"verified_flags":verified_all,"exact_flags":exact,"kinds":kinds,"evidence_board":evidence,"top_findings":evidence,"top_chains":chains,"agents":sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:120],"transformations":sorted(transforms,key=lambda x:x.get("score",0),reverse=True)[:200],"artifacts":artifacts,"recipes":recipes,"artifact_graphs":graphs[:100],"verifyloops":verifyloops[:120],"hypotheses":workflowbrain_project_hypotheses(reports) if "workflowbrain_project_hypotheses" in globals() else [],"workflow_steps":sorted(workflow+actions,key=lambda x:x.get("priority",0),reverse=True)[:140],"missing_tools":sorted(set(missing))[:100],"priority_files":priority}
    summary["health"]=cl_project_health(reports, summary) if "cl_project_health" in globals() else {"status":"solved" if flags else ("answer_candidates" if answers else "needs_review")}
    summary["unresolved_plan"]=cl_unresolved_plan(reports) if "cl_unresolved_plan" in globals() else []
    return summary
def dp_raw_transform_bfs(label, text, max_depth=5, beam=40):
    """Fast structural transform BFS. No ROT spam in automatic batch path."""
    from collections import deque
    seeds=dp_extract_decode_seeds(text)[:60]
    q=deque({"text":v,"path":label+":"+k,"depth":0} for k,v in seeds)
    results=[]; seen=set(); states=0
    while q and states<700 and len(results)<120:
        cur=q.popleft(); states+=1
        txt=cur["text"][:12000]
        key=(cur["depth"],txt[:400])
        if key in seen: continue
        seen.add(key)
        flags=vf_primary_flags(txt,limit=10,scan_limit=12000)
        if flags:
            results.append({"type":"realbench_raw_bfs","input":cur["path"],"output":txt,"flags":flags,"score":score_text(txt)+350-cur["depth"]*10,"chain_source":cur["path"]})
        if cur["depth"]>=max_depth: continue
        # Structural transforms only: split/base/hex/url/html/reverse.
        for name,out in dp_basic_transforms_structural(txt, include_rot=False):
            if not out or out==txt: continue
            if vf_primary_flags(out,limit=1) or dp_is_mostly_printable(out) or re.search(r"[A-Za-z0-9+/=_-]{12,}|[A-Fa-f0-9]{16,}",out):
                q.append({"text":out[:12000],"path":cur["path"]+" -> "+name,"depth":cur["depth"]+1})
    out=[]; seen2=set()
    for r in sorted(results,key=lambda x:x.get("score",0),reverse=True):
        k=(r.get("chain_source",""),r.get("output","")[:260])
        if k not in seen2:
            seen2.add(k); out.append(r)
    return out[:80]
def deeppattern_enhance(report, root, data):
    """Fast automatic enhancement. Heavy ROT/search is not run in batch path."""
    text=dp_collect_text(report)[:30000]
    extra_chain=[]
    # Only high-signal full text and individual payloads.
    extra_chain += dp_raw_transform_bfs("RealBench fast BFS", text, max_depth=5, beam=35)
    for s in report.get("strings",[])[:120]:
        if any(x in s.lower() for x in ["ctf","flag","eyj","rsa","base","xor","blob","token","answer","atsakymas"]) or re.search(r"[A-Za-z0-9+/=_-]{16,}|[A-Fa-f0-9]{20,}",s):
            extra_chain += dp_raw_transform_bfs("RealBench string", s, max_depth=5, beam=20)[:20]
    # XOR crib only for binary-ish/high entropy or when no plain flag found.
    if data and (report.get("entropy",0)>4.5 or not report.get("flags")):
        for x in dp_xor_key_from_crib(data)[:20]:
            extra_chain.append({"type":x["type"],"input":x.get("key_hex",""),"output":x["output"],"flags":x.get("flags",[]),"score":x.get("score",0),"chain_source":"RealBench XOR crib key="+x.get("key_text","")})
    extra_chain += dp_jwt_decode(text)[:20]
    seen=set((c.get("type"),(c.get("output","") or "")[:220]) for c in report.get("chain_results",[]))
    for c in sorted(extra_chain,key=lambda x:x.get("score",0),reverse=True):
        k=(c.get("type"),(c.get("output","") or "")[:220])
        if k not in seen:
            seen.add(k); report.setdefault("chain_results",[]).insert(0,c)
            for f in c.get("flags",[]) or []:
                if f not in report.setdefault("flags",[]): report["flags"].append(f)
    report["chain_results"]=sorted(report.get("chain_results",[]),key=lambda x:x.get("score",0),reverse=True)[:180]
    # Save only top flagged/high-value deep outputs.
    for i,c in enumerate(report.get("chain_results",[])[:20]):
        if (c.get("flags") or c.get("score",0)>140) and str(c.get("type","")).lower().startswith(("realbench","deeppattern")):
            art=dp_write_artifact(root,report,f"realbench_chain_{i:02d}_{safe(c.get('type','out'))}.txt",c.get("output",""),"realbench_chain",c.get("score",0))
            if art:
                report.setdefault("artifacts",[]).insert(0,art)
                report.setdefault("transformations",[]).append(art)
    # Image LSB variants are useful but bounded.
    if report.get("kind")=="image":
        arts=dp_lsb_bit_order_variants(Path(report.get("path","")),root,report)
        report.setdefault("artifacts",[]).extend(arts)
        report.setdefault("transformations",[]).extend(arts)
        for art in arts:
            try:
                txt=Path(art["path"]).read_text(encoding="utf-8",errors="ignore")[:12000]
                for f in vf_primary_flags(txt,limit=8):
                    if f not in report.setdefault("flags",[]): report["flags"].append(f)
            except Exception: pass
    return report
PLACEHOLDER_INNERS = {
    "...","sample","sample_flag","sample_test","dummy","dummy_test","fake","fake_flag",
    "placeholder","your_flag","flag_here","insert_flag","change_me","todo","example"
}
def smartsolve_strict_target_flag_ok(flag, meta=None):
    flag=str(flag or "").strip()
    if not STRICT_PRIMARY_FLAG_RE.fullmatch(flag):
        return False
    inner=flag_inner(flag)
    low=inner.lower().strip()
    if low in PLACEHOLDER_INNERS:
        return False
    if any(x in low for x in ["placeholder","your_flag","not_the_flag","notflag","insert_flag","change_me"]):
        return False
    if len(inner)<5 or len(inner)>120:
        return False
    if any(ord(c)<32 or ord(c)>126 for c in inner):
        return False
    if "ctf_cs" in low:
        return False
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_\-:.+]{4,120}", inner):
        return False
    return True
def dp_flag_score(flag):
    return 100 if smartsolve_strict_target_flag_ok(flag) else -100
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
def mb_blob_seeds(text):
    text=str(text or "")[:60000]
    seeds=[]
    def add(label,val):
        val=str(val or "").strip().strip("'\"`")
        if len(val)>=4:
            seeds.append((label,val[:20000]))
    add("full", text)
    # JSON / key-value / Lithuanian prompt blobs
    for m in re.finditer(r"\b[A-Za-z0-9_.-]{1,40}\s*[:=]\s*([A-Za-z0-9+/=_\-.]{8,})", text):
        add("key_value", m.group(1))
    for m in re.finditer(r"(?:blob|data|token|secret|raktas|slapta|atsakymas|answer)\s*[:=]\s*([^\s'\"<>]{4,})", text, re.I):
        add("answer_blob", m.group(1))
    for m in re.finditer(r"[A-Za-z0-9+/=_-]{12,}|[A-Fa-f0-9]{16,}|(?:[01]{8}\s*){2,}|(?:\d{2,3}[,\s]+){3,}\d{2,3}", text):
        add("long_token", m.group(0))
    # de-dupe
    out=[]; seen=set()
    for label,val in seeds:
        k=val[:400]
        if k not in seen:
            seen.add(k); out.append((label,val))
    return out[:180]
def mb_basic_decode_steps(s):
    s=str(s or "").strip()
    outs=[]
    seen=set()
    def add(name,out):
        out=str(out or "")[:20000]
        if out and out!=s and (name,out[:300]) not in seen:
            seen.add((name,out[:300])); outs.append((name,out))
    compact=re.sub(r"\s+","",s)
    try:
        u=urllib.parse.unquote(s)
        if u!=s: add("url",u)
    except Exception: pass
    try:
        h=html.unescape(s)
        if h!=s: add("html",h)
    except Exception: pass
    try:
        if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}",compact):
            padded=compact+"="*((4-len(compact)%4)%4)
            add("base64",base64.b64decode(padded,validate=False).decode("utf-8","replace"))
            add("base64url",base64.urlsafe_b64decode(padded).decode("utf-8","replace"))
    except Exception: pass
    try:
        if len(compact)%2==0 and re.fullmatch(r"[A-Fa-f0-9]{8,}",compact):
            add("hex",bytes.fromhex(compact).decode("utf-8","replace"))
    except Exception: pass
    try:
        if re.fullmatch(r"[A-Z2-7=]{8,}",compact):
            add("base32",base64.b32decode(compact+"="*((8-len(compact)%8)%8)).decode("utf-8","replace"))
    except Exception: pass
    try:
        if re.fullmatch(r"[01]{16,}",compact) and len(compact)%8==0 and len(compact)<=20000:
            bs=bytes(int(compact[i:i+8],2) for i in range(0,len(compact),8))
            add("binary_ascii",bs.decode("utf-8","replace"))
    except Exception: pass
    try:
        nums=re.findall(r"\b\d{2,3}\b",s)
        if 3<=len(nums)<=300:
            bs=bytes(int(n)&255 for n in nums)
            add("decimal_ascii",bs.decode("utf-8","replace"))
    except Exception: pass
    if len(s)<=8000:
        add("reverse",s[::-1])
    return outs
def mb_fast_chain(text, max_depth=7, state_limit=1800):
    from collections import deque
    q=deque({"text":v,"path":label,"depth":0} for label,v in mb_blob_seeds(text))
    results=[]; seen=set(); states=0
    while q and states<state_limit and len(results)<300:
        cur=q.popleft(); states+=1
        txt=cur["text"][:20000]
        k=(cur["depth"],txt[:500])
        if k in seen: continue
        seen.add(k)
        flags=vf_primary_flags(txt,limit=10,scan_limit=20000)
        if flags:
            results.append({"type":"megabench_chain","input":cur["path"],"output":txt[:12000],"flags":flags,"score":score_text(txt)+350-cur["depth"]*5,"chain_source":cur["path"]})
        if cur["depth"]>=max_depth: continue
        for name,out in mb_basic_decode_steps(txt):
            if not out: continue
            if vf_primary_flags(out,limit=1) or dp_is_mostly_printable(out[:3000]) or re.search(r"[A-Za-z0-9+/=_-]{12,}|[A-Fa-f0-9]{16,}",out):
                q.append({"text":out[:20000],"path":cur["path"]+" -> "+name,"depth":cur["depth"]+1})
    out=[]; seen2=set()
    for r in sorted(results,key=lambda x:x.get("score",0),reverse=True):
        k=(r.get("chain_source",""),r.get("output","")[:300])
        if k not in seen2:
            seen2.add(k); out.append(r)
    return out[:120]
def mb_caesar_and_vigenere_candidates(text):
    """Bounded classical pass for direct ctf-like strings, not full brute spam."""
    text=str(text or "")[:12000]
    outs=[]
    # Caesar only if text has ctf-ish/brace-ish context or all-caps phrase.
    alphabet="abcdefghijklmnopqrstuvwxyz"
    for r in range(1,26):
        rot=dp_rot_text(text,r)
        flags=vf_primary_flags(rot,limit=6,scan_limit=12000)
        if flags:
            outs.append({"type":"megabench_caesar","input":f"rot{r}","output":rot[:12000],"flags":flags,"score":260,"chain_source":f"rot{r}"})
    # Atbash
    try:
        src="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        dst="zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"
        at=text.translate(str.maketrans(src,dst))
        flags=vf_primary_flags(at,limit=6,scan_limit=12000)
        if flags:
            outs.append({"type":"megabench_atbash","input":"atbash","output":at[:12000],"flags":flags,"score":255,"chain_source":"atbash"})
    except Exception:
        pass
    return outs[:30]
def mb_xor_short_keys(data):
    """Extra bounded XOR: single-byte and few likely keys."""
    outs=[]
    data=bytes(data or b"")[:80000]
    for x in xor_single(data)[:20]:
        if x.get("flags"):
            outs.append({"type":"megabench_xor_single","input":x.get("type",""),"output":x.get("output",""),"flags":x.get("flags",[]),"score":x.get("score",0)+60,"chain_source":"xor_single"})
    for x in dp_xor_key_from_crib(data)[:30]:
        if x.get("flags"):
            outs.append({"type":"megabench_xor_crib","input":x.get("key_hex",""),"output":x.get("output",""),"flags":x.get("flags",[]),"score":x.get("score",0)+80,"chain_source":"xor_crib key="+x.get("key_text","")})
    return sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:40]
def mb_collect_strong_answers(report):
    """More aggressive non-format answer pickup, but still separated from flags."""
    extra=[]
    text="\n".join(report.get("strings",[])[:1200])+"\n"+"\n".join((o.get("out") or "")[:5000] for o in report.get("outputs",[])[:80])
    text+="\n"+"\n".join((c.get("output") or "")[:4000] for c in report.get("chain_results",[])[:80])
    # named captures after Lithuanian / English prompts
    for m in re.finditer(r"(?:atsakymas|ats|raktas|slaptažodis|slaptazodis|slapta|kodas|answer|key|password|pass|secret|code|token)\s*[:=]\s*([A-Za-z0-9_\-:.+/@]{3,160})", text, re.I):
        extra.append({"value":m.group(1),"source":"megabench_named_capture","why":"value after answer/key/password marker","score":145})
    # URL tokens, coords, hashes
    for m in re.finditer(r"\b[A-Fa-f0-9]{32,64}\b", text):
        extra.append({"value":m.group(0),"source":"megabench_hash","why":"hash-like candidate","score":125})
    for m in re.finditer(r"-?\d{1,3}\.\d{3,},\s*-?\d{1,3}\.\d{3,}", text):
        extra.append({"value":m.group(0),"source":"megabench_coordinates","why":"coordinate-like answer candidate","score":130})
    # Markdown/code style hints.
    for m in re.finditer(r"`([^`\n]{4,120})`", text):
        val=m.group(1).strip()
        if vf_answer_score(val,"backtick")>=55:
            extra.append({"value":val,"source":"megabench_backticks","why":"backticked value in text/decoded output","score":vf_answer_score(val,"backtick")+35})
    out=[]; seen=set()
    for x in sorted(extra,key=lambda z:z.get("score",0),reverse=True):
        k=x["value"].lower()
        if k not in seen:
            seen.add(k); out.append(x)
    return out[:80]
def deeppattern_enhance(report, root, data):
    """v32 fast but stronger automatic enhancement."""
    text=dp_collect_text(report)[:45000]
    extra=[]
    extra += mb_fast_chain(text,max_depth=7,state_limit=1600)
    # Individual lines/tokens.
    for s in report.get("strings",[])[:180]:
        if any(x in s.lower() for x in ["ctf","flag","eyj","rsa","base","xor","blob","token","answer","atsakymas","raktas","key","secret","slapta"]) or re.search(r"[A-Za-z0-9+/=_-]{16,}|[A-Fa-f0-9]{20,}",s):
            extra += mb_fast_chain(s,max_depth=7,state_limit=500)[:30]
            extra += mb_caesar_and_vigenere_candidates(s)[:10]
    extra += mb_caesar_and_vigenere_candidates(text)[:10]
    if data and (report.get("entropy",0)>3.8 or not report.get("flags")):
        extra += mb_xor_short_keys(data)
    extra += dp_jwt_decode(text)[:30]
    # Decompression outputs in artifacts feed back into chain.
    for a in report.get("artifacts",[])[:80]:
        p=Path(a.get("path",""))
        try:
            if p.exists() and p.is_file() and p.stat().st_size<700000:
                txt=p.read_text(encoding="utf-8",errors="ignore")[:12000]
                extra += mb_fast_chain(txt,max_depth=5,state_limit=400)[:20]
        except Exception:
            pass
    seen=set((c.get("type"),(c.get("output","") or "")[:240]) for c in report.get("chain_results",[]))
    for c in sorted(extra,key=lambda x:x.get("score",0),reverse=True):
        k=(c.get("type"),(c.get("output","") or "")[:240])
        if k not in seen:
            seen.add(k); report.setdefault("chain_results",[]).insert(0,c)
            for f in c.get("flags",[]) or []:
                if f not in report.setdefault("flags",[]): report["flags"].append(f)
    report["chain_results"]=sorted(report.get("chain_results",[]),key=lambda x:x.get("score",0),reverse=True)[:220]
    for i,c in enumerate(report.get("chain_results",[])[:24]):
        if c.get("flags") or c.get("score",0)>160:
            art=dp_write_artifact(root,report,f"megabench_chain_{i:02d}_{safe(c.get('type','out'))}.txt",c.get("output",""),"megabench_chain",c.get("score",0))
            if art:
                report.setdefault("artifacts",[]).insert(0,art)
                report.setdefault("transformations",[]).append(art)
    if report.get("kind")=="image":
        arts=dp_lsb_bit_order_variants(Path(report.get("path","")),root,report)
        report.setdefault("artifacts",[]).extend(arts)
        report.setdefault("transformations",[]).extend(arts)
        for art in arts:
            try:
                txt=Path(art["path"]).read_text(encoding="utf-8",errors="ignore")[:12000]
                for f in vf_primary_flags(txt,limit=8):
                    if f not in report.setdefault("flags",[]): report["flags"].append(f)
            except Exception: pass
    return report
def vf_collect_answer_candidates(report):
    cands=[]
    for f in report.get("flags",[])[:80]:
        vf_add_answer(cands,f,"promoted flag","strict ctf_cs candidate",250)
    for v in report.get("verified_flags",[])[:80]:
        vf_add_answer(cands,v.get("flag",""),"verified_flags","; ".join(v.get("reasons",[])[:3]),int(v.get("score",0)//4))
    joined="\n".join(report.get("strings",[])[:1200])+"\n"+"\n".join((o.get("out") or "")[:5000] for o in report.get("outputs",[])[:80])
    joined+="\n"+"\n".join((c.get("output") or "")[:4000] for c in report.get("chain_results",[])[:80])
    for alt in vf_alt_ctf_candidates(joined,limit=20):
        cands.append({"value":alt,"source":"alternate_ctf_like","why":"Not promoted because only ctf_cs{...} is auto-promoted.","score":90})
    for line in joined.splitlines()[:2500]:
        line=line.strip(); low=line.lower()
        if not (4<=len(line)<=260): continue
        if any(k in low for k in ["answer","atsakymas","ats:","raktas","key","secret","slapta","slaptažodis","slaptazodis","password","pass","code","kodas","token","login","vartotojas"]):
            vf_add_answer(cands,line,"strings/chains","answer-like line",45)
            m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|slaptazodis|password|pass|code|kodas|token|login|vartotojas)\s*[:=]\s*(.+)$",line,re.I)
            if m: vf_add_answer(cands,m.group(1).strip(),"strings/chains","value after marker",85)
    cands += mb_collect_strong_answers(report)
    # OCR/QR and artifacts, bounded.
    for p in report.get("previews",[])[:80]:
        txt=((p.get("ocr","") or "")+"\n"+(p.get("qr","") or "")).strip()
        for f in vf_primary_flags(txt,limit=4):
            vf_add_answer(cands,f,"visual_ocr_qr:"+str(p.get("name","")),"OCR/QR",int(p.get("score",0)//4)+90)
        for line in txt.splitlines()[:30]:
            if 3<=len(line.strip())<=160:
                vf_add_answer(cands,line.strip(),"visual_ocr:"+str(p.get("name","")),"OCR text",int(p.get("score",0)//8)+20)
    for a in report.get("artifacts",[])[:100]:
        p=Path(a.get("path",""))
        try:
            if not p.exists() or not p.is_file() or p.stat().st_size>=600000: continue
            if not (p.suffix.lower() in [".txt",".json",".log",".md",".csv",".xml"] or any(x in p.name.lower() for x in ["ocr","decoded","answer","secret","key","brief","strings","fallback","constants","chain"])):
                continue
            txt=p.read_text(encoding="utf-8",errors="ignore")[:10000]
            for f in vf_primary_flags(txt,limit=5):
                vf_add_answer(cands,f,"artifact:"+a.get("kind",""),"artifact text",int(a.get("score",0)//3)+80)
            for line in txt.splitlines()[:100]:
                line=line.strip(); low=line.lower()
                if 4<=len(line)<=200 and any(k in low for k in ["answer","atsakymas","ats:","raktas","key","secret","slapta","slaptažodis","slaptazodis","password","pass","code","kodas","token"]):
                    vf_add_answer(cands,line,"artifact_context:"+a.get("kind",""),"answer-like artifact line",int(a.get("score",0)//5)+35)
                    m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|slaptazodis|password|pass|code|kodas|token)\s*[:=]\s*(.+)$",line,re.I)
                    if m: vf_add_answer(cands,m.group(1).strip(),"artifact_value:"+a.get("kind",""),"value after marker",int(a.get("score",0)//5)+75)
        except Exception:
            pass
    out=[]; seen=set()
    for x in sorted(cands,key=lambda z:z.get("score",0),reverse=True):
        k=x.get("value","").lower()
        if k and k not in seen:
            seen.add(k); out.append(x)
    return out[:180]
def mb_gen_cases():
    import base64 as _b64, urllib.parse as _url, gzip as _gzip, zlib as _zlib, bz2 as _bz2, lzma as _lzma
    cases=[]
    def add(name, kind, blob, expected, mode="text"):
        cases.append({"name":name,"kind":kind,"blob":blob,"expected":expected,"mode":mode})
    # 40 encoding stacks
    for i in range(40):
        flag=f"ctf_cs{{mb_enc_{i:02d}_ok}}".encode()
        if i%8==0: blob=_b64.b64encode(flag).decode()
        elif i%8==1: blob=_b64.b64encode(_b64.b64encode(flag)).decode()
        elif i%8==2: blob=_b64.b64encode(flag).decode().encode().hex()
        elif i%8==3: blob=_b64.b64encode(_b64.b64encode(flag).decode().encode().hex().encode()).decode()
        elif i%8==4: blob=_url.quote(_b64.b64encode(flag).decode())
        elif i%8==5: blob=" ".join(str(b) for b in flag)
        elif i%8==6: blob="".join(f"{b:08b}" for b in flag)
        else: blob=_b64.b32encode(flag).decode()
        add(f"encoding_{i:02d}","encoding","blob="+blob,flag.decode())
    # 20 XOR
    for i in range(20):
        flag=f"ctf_cs{{mb_xor_{i:02d}_ok}}".encode()
        key=[b"k",b"xy",b"key",b"flag"][i%4]
        plain=b"noise::"+flag+b"::end"
        enc=bytes(b ^ key[j%len(key)] for j,b in enumerate(plain))
        add(f"xor_{i:02d}","xor",enc,flag.decode(),"bytes")
    # 15 compressed
    compressors=[("gz",_gzip.compress),("zlib",_zlib.compress),("bz2",_bz2.compress),("xz",_lzma.compress)]
    for i in range(15):
        flag=f"ctf_cs{{mb_comp_{i:02d}_ok}}".encode()
        nm,fn=compressors[i%len(compressors)]
        add(f"compressed_{i:02d}_{nm}","compressed",fn(b"data "+flag+b"\n"),flag.decode(),"bytes")
    # 10 JWT/baseurl-ish
    for i in range(10):
        flag=f"ctf_cs{{mb_jwt_{i:02d}_ok}}"
        h=_b64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        p=_b64.urlsafe_b64encode(json.dumps({"msg":flag}).encode()).decode().rstrip("=")
        add(f"jwt_{i:02d}","jwt","token="+h+"."+p+".",flag)
    # 15 non-format answers
    for i in range(15):
        ans=f"answerword{i:02d}"
        add(f"answer_{i:02d}","answer",f"Užduotis\natsakymas: {ans}\n",ans)
    return cases[:100]
def mb_run_100_benchmark():
    cases=mb_gen_cases()
    results=[]
    for c in cases:
        expected=c["expected"]
        blob=c["blob"]
        text=blob.decode("latin1","ignore") if isinstance(blob,(bytes,bytearray)) else str(blob)
        found_flags=[]
        answers=[]
        # Fast chain on text.
        chain=mb_fast_chain(text,max_depth=7,state_limit=900)
        found_flags += vf_primary_flags(text,limit=10,scan_limit=50000)
        found_flags += [f for item in chain for f in item.get("flags",[])]
        # Compressed/direct bytes.
        data=bytes(blob) if isinstance(blob,(bytes,bytearray)) else text.encode()
        fake_report={"flags":found_flags,"verified_flags":[],"strings":[text],"outputs":[{"ok":True,"out":text}],"chain_results":chain,"previews":[],"artifacts":[]}
        # XOR/comp direct
        for item in mb_xor_short_keys(data):
            found_flags += item.get("flags",[])
        for item in try_decompress_bytes(data)[:10]:
            out=item.get("output","")
            found_flags += vf_primary_flags(out,limit=10,scan_limit=50000)
            fake_report["chain_results"].append({"type":item.get("type"),"output":out,"score":item.get("score",0),"flags":vf_primary_flags(out)})
        fake_report["flags"]=list(dict.fromkeys(found_flags))
        answers=[a["value"] for a in vf_collect_answer_candidates(fake_report)]
        ok=(expected in found_flags) or (expected in answers) or (expected in json.dumps(chain))
        results.append({"name":c["name"],"kind":c["kind"],"expected":expected,"ok":ok,"flags":list(dict.fromkeys(found_flags))[:10],"answers":answers[:10]})
    passed=sum(1 for r in results if r["ok"])
    by_kind={}
    for r in results:
        by_kind.setdefault(r["kind"],{"ok":0,"total":0})
        by_kind[r["kind"]]["total"]+=1
        by_kind[r["kind"]]["ok"]+=1 if r["ok"] else 0
    return {"ok":passed==len(results),"passed":passed,"total":len(results),"by_kind":by_kind,"results":results}
async def mega_benchmark_endpoint():
    try:
        return mb_run_100_benchmark()
    except Exception as e:
        return {"ok":False,"error":str(e)}
async def mega_benchmark_get_endpoint():
    try:
        return mb_run_100_benchmark()
    except Exception as e:
        return {"ok":False,"error":str(e)}
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MORSE = {
    ".-":"a","-...":"b","-.-.":"c","-..":"d",".":"e","..-.":"f","--.":"g","....":"h","..":"i",".---":"j",
    "-.-":"k",".-..":"l","--":"m","-.":"n","---":"o",".--.":"p","--.-":"q",".-.":"r","...":"s","-":"t",
    "..-":"u","...-":"v",".--":"w","-..-":"x","-.--":"y","--..":"z","-----":"0",".----":"1","..---":"2",
    "...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"
}
BRAILLE_MAP = {
    "⠁":"a","⠃":"b","⠉":"c","⠙":"d","⠑":"e","⠋":"f","⠛":"g","⠓":"h","⠊":"i","⠚":"j",
    "⠅":"k","⠇":"l","⠍":"m","⠝":"n","⠕":"o","⠏":"p","⠟":"q","⠗":"r","⠎":"s","⠞":"t",
    "⠥":"u","⠧":"v","⠺":"w","⠭":"x","⠽":"y","⠵":"z","⠼":"#"
}
def ff_base58_decode(s):
    s=str(s or "").strip()
    if not s or any(c not in B58_ALPHABET for c in s):
        return None
    n=0
    for c in s:
        n=n*58+B58_ALPHABET.index(c)
    b=n.to_bytes((n.bit_length()+7)//8,"big") if n else b""
    pad=0
    for c in s:
        if c=="1": pad+=1
        else: break
    return b"\x00"*pad+b
def ff_morse_decode(s):
    s=str(s or "").strip()
    if not re.fullmatch(r"[.\-/|\s]+",s) or "." not in s:
        return None
    words=[]
    for word in re.split(r"\s*/\s*|\s{3,}|\|",s):
        letters=[]
        for token in re.split(r"\s+",word.strip()):
            if token in MORSE:
                letters.append(MORSE[token])
            elif token:
                return None
        if letters:
            words.append("".join(letters))
    return " ".join(words) if words else None
def ff_bacon_decode(s):
    s=re.sub(r"[^ABab01]", "", str(s or ""))
    if len(s)<5 or len(s)%5!=0:
        return None
    out=[]
    for i in range(0,len(s),5):
        chunk=s[i:i+5].lower().replace("0","a").replace("1","b")
        val=0
        for c in chunk:
            val=(val<<1)+(1 if c=="b" else 0)
        if 0<=val<26:
            out.append(chr(ord("a")+val))
        else:
            return None
    return "".join(out)
def ff_braille_decode(s):
    s=str(s or "")
    if not any(c in BRAILLE_MAP for c in s):
        return None
    return "".join(BRAILLE_MAP.get(c,c) for c in s)
def ff_extra_decoders(text):
    """Additional CTF decoders kept bounded."""
    text=str(text or "")[:50000]
    outs=[]; seen=set()
    def add(t,inp,out,bonus=0):
        if out is None: return
        out=str(out)[:20000]
        if not out.strip(): return
        k=(t,out[:300])
        if k in seen: return
        seen.add(k)
        flags=vf_primary_flags(out,limit=8,scan_limit=20000)
        sc=score_text(out)+bonus+(180 if flags else 0)
        if flags or sc>=45:
            outs.append({"type":"flowforge_"+t,"input":str(inp)[:180],"output":out,"flags":flags,"score":sc,"chain_source":"FlowForge extra decoder"})
    # Morse chunks
    for m in re.finditer(r"(?:[.\-]{1,6}[\s/|]+){3,}[.\-]{1,6}", text):
        add("morse",m.group(0),ff_morse_decode(m.group(0)),65)
    # Base58-ish tokens
    for m in re.finditer(r"\b[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{12,160}\b", text):
        tok=m.group(0)
        try:
            b=ff_base58_decode(tok)
            if b:
                add("base58",tok,b.decode("utf-8","replace"),60)
        except Exception:
            pass
    # Bacon A/B or 0/1 in separated groups
    for m in re.finditer(r"\b[ABab01]{20,300}\b", text):
        add("bacon",m.group(0),ff_bacon_decode(m.group(0)),55)
    # Braille
    for line in text.splitlines()[:800]:
        if any(c in BRAILLE_MAP for c in line):
            add("braille",line,ff_braille_decode(line),60)
    # JSON secrets
    for m in re.finditer(r'"(?:flag|answer|atsakymas|raktas|key|secret|password|token|code|kodas)"\s*:\s*"([^"]{3,220})"', text, re.I):
        add("json_secret",m.group(0),m.group(1),75)
    return sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:80]
def ff_statement_text(report):
    txt=""
    try:
        root=Path(report.get("path","")).parents[1]
        meta=jread(root/"project.json",{})
        txt=(meta.get("statement","") or "")+"\n"+(meta.get("title","") or "")+"\n"+(meta.get("category","") or "")
    except Exception:
        pass
    return txt
def ff_statement_keywords(text):
    low=str(text or "").lower()
    keys=[]
    mapping={
        "image":["png","jpg","jpeg","nuotrauka","paveiksl","image","foto","krum","mišk","misk","matosi","raid"],
        "pcap":["pcap","wireshark","tinklas","network","packet","dns","http","tcp"],
        "archive":["zip","archive","archyv","rar","7z","tar","slaptažodis","password"],
        "crypto":["crypto","šif","sif","cipher","decode","encoded","base64","xor","rsa","hash","jwt"],
        "rev":["rev","reverse","exe","elf","binary","pyc","decompile","program"],
        "web":["web","cookie","jwt","html","server","url","request"],
        "osint":["osint","location","viet","žemėlap","zemelap","google","koordin"],
    }
    for k,words in mapping.items():
        if any(w in low for w in words):
            keys.append(k)
    return keys
def ff_candidate_to_flag_helpers(report):
    """Show likely wrapping helpers but do not promote unless exact ctf_cs found."""
    helpers=[]
    for a in report.get("answer_candidates",[])[:60]:
        val=str(a.get("value","")).strip()
        if not val or val.lower().startswith("ctf_cs{"):
            continue
        clean=val
        # Extract right side if full line
        m=re.search(r"[:=]\s*([A-Za-z0-9_\-:.+/@]{3,160})\s*$",clean)
        if m:
            clean=m.group(1)
        # make safe flag body suggestion
        body=re.sub(r"\s+","_",clean.strip())
        body=re.sub(r"[^A-Za-z0-9_\-:.+]","",body)
        if 3<=len(body)<=100:
            helpers.append({"answer":val,"suggested_flag":f"ctf_cs{{{body}}}","source":a.get("source",""),"score":a.get("score",0)-5,"why":"Non-format answer candidate. Try wrapping only if challenge expects flag wrapper."})
    out=[]; seen=set()
    for h in sorted(helpers,key=lambda x:x.get("score",0),reverse=True):
        k=h["suggested_flag"].lower()
        if k not in seen:
            seen.add(k); out.append(h)
    return out[:50]
def ff_write_artifact(root, report, name, content, kind="flowforge_artifact", score=80):
    outdir=root/"generated"/"flowforge"/safe(report.get("name","file"))
    outdir.mkdir(parents=True,exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        return {"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"FlowForge","score":score,"note":"FlowForge generated artifact","exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
    except Exception:
        return None
def ff_child_artifact_autopass(root, report, max_children=40):
    """Analyze useful generated child artifacts shallowly, feeding results back into parent."""
    extra_chain=[]; new_answers=[]; arts=[]
    seen=set()
    for a in report.get("artifacts",[])[:160]:
        p=Path(a.get("path",""))
        if not p.exists() or not p.is_file(): continue
        if p.stat().st_size>1_200_000: continue
        if p in seen: continue
        seen.add(p)
        try:
            data=p.read_bytes()
        except Exception:
            continue
        txt=data.decode("utf-8","ignore")
        if not txt and p.suffix.lower() not in [".bin",".dat",".raw",".txt",".json",".log"]:
            continue
        # Fast decode child text
        for c in mb_fast_chain(txt,max_depth=6,state_limit=500)[:20]:
            c=dict(c); c["chain_source"]="child_artifact:"+a.get("name","")+" -> "+c.get("chain_source","")
            c["score"]=c.get("score",0)+int(a.get("score",0)//10)
            extra_chain.append(c)
        extra_chain += ff_extra_decoders(txt)[:15]
        for f in vf_primary_flags(txt,limit=10,scan_limit=30000):
            if f not in report.setdefault("flags",[]):
                report["flags"].append(f)
        # Try decompression on child binary
        for d in try_decompress_bytes(data)[:6]:
            if d.get("output"):
                art=ff_write_artifact(root,report,"child_decompressed_"+safe(p.name)+"_"+safe(d.get("type","out"))+".txt",d.get("output",""),"flowforge_child_decompressed",120 if d.get("flags") else 80)
                if art: arts.append(art)
                extra_chain.append({"type":"flowforge_child_decompress","input":p.name,"output":d.get("output",""),"flags":d.get("flags",[]),"score":d.get("score",0)+70,"chain_source":"child decompress "+p.name})
        if len(seen)>=max_children:
            break
    if arts:
        existing=set(x.get("path") for x in report.get("artifacts",[]))
        for a in arts:
            if a.get("path") not in existing:
                report.setdefault("artifacts",[]).append(a)
                report.setdefault("transformations",[]).append(a)
                existing.add(a.get("path"))
    if extra_chain:
        old=set((c.get("type"),(c.get("output","") or "")[:240]) for c in report.get("chain_results",[]))
        for c in sorted(extra_chain,key=lambda x:x.get("score",0),reverse=True):
            k=(c.get("type"),(c.get("output","") or "")[:240])
            if k not in old:
                old.add(k); report.setdefault("chain_results",[]).insert(0,c)
                for f in c.get("flags",[]) or []:
                    if f not in report.setdefault("flags",[]): report["flags"].append(f)
        report["chain_results"]=sorted(report.get("chain_results",[]),key=lambda x:x.get("score",0),reverse=True)[:260]
    return report
def ff_autopilot_review(report):
    top_flag=(report.get("flags") or [""])[0] if report.get("flags") else ""
    top_answer=(report.get("answer_candidates") or [{}])[0].get("value","") if report.get("answer_candidates") else ""
    top_art=(report.get("artifacts") or [{}])[0]
    top_chain=(report.get("chain_results") or [{}])[0]
    statement=ff_statement_text(report)
    keys=ff_statement_keywords(statement)
    status="solved_flag" if top_flag else ("answer_candidate" if top_answer else ("has_artifacts" if report.get("artifacts") else "needs_manual"))
    actions=[]
    if top_flag:
        actions.append("Submit/check promoted ctf_cs flag.")
    if top_answer and not top_flag:
        actions.append("Open Answer Candidates; try direct answer or suggested wrapper if competition requires ctf_cs{...}.")
    if report.get("kind")=="image" or "image" in keys:
        actions.append("Open Visual Lab contact sheet and rotation/filter outputs.")
    if report.get("artifacts"):
        actions.append("Open top artifact and inspect/copy path.")
    if report.get("chain_results"):
        actions.append("Open Chain results and copy top decoded output.")
    if not actions:
        actions.append("Run manual Deep Suite / specific category tools.")
    return {"status":status,"statement_keywords":keys,"top_flag":top_flag,"top_answer":top_answer,"top_artifact":top_art,"top_chain":{"type":top_chain.get("type",""),"score":top_chain.get("score",0),"source":top_chain.get("chain_source","")},"actions":actions}
def vf_collect_answer_candidates(report):
    cands=[]
    for f in report.get("flags",[])[:100]:
        vf_add_answer(cands,f,"promoted flag","strict ctf_cs candidate",250)
    for v in report.get("verified_flags",[])[:100]:
        vf_add_answer(cands,v.get("flag",""),"verified_flags","; ".join(v.get("reasons",[])[:3]),int(v.get("score",0)//4))
    statement=ff_statement_text(report)
    joined=statement+"\n"+"\n".join(report.get("strings",[])[:1400])+"\n"+"\n".join((o.get("out") or "")[:5000] for o in report.get("outputs",[])[:100])
    joined+="\n"+"\n".join((c.get("output") or "")[:5000] for c in report.get("chain_results",[])[:100])
    # Statement hints improve scoring.
    hint_bonus=25 if statement else 0
    for alt in vf_alt_ctf_candidates(joined,limit=20):
        cands.append({"value":alt,"source":"alternate_ctf_like","why":"Not promoted because only ctf_cs{...} is auto-promoted.","score":90})
    markers=["answer","atsakymas","ats","raktas","key","secret","slapta","slaptažodis","slaptazodis","password","pass","code","kodas","token","login","vartotojas","user","username"]
    for line in joined.splitlines()[:3200]:
        line=line.strip(); low=line.lower()
        if not (3<=len(line)<=300): continue
        if any(k in low for k in markers):
            vf_add_answer(cands,line,"statement/strings/chains","answer-like line",50+hint_bonus)
            m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|slaptazodis|password|pass|code|kodas|token|login|vartotojas|user|username)\s*[:=]\s*(.+)$",line,re.I)
            if m: vf_add_answer(cands,m.group(1).strip(),"statement/strings/chains","value after marker",95+hint_bonus)
    cands += mb_collect_strong_answers(report)
    # Extra decoded answer values from FlowForge decoders
    for c in report.get("chain_results",[])[:100]:
        out=(c.get("output","") or "")[:5000]
        for f in vf_primary_flags(out,limit=6):
            vf_add_answer(cands,f,"chain:"+str(c.get("type","")),"decoded output",int(c.get("score",0)//4)+95)
    for p in report.get("previews",[])[:100]:
        txt=((p.get("ocr","") or "")+"\n"+(p.get("qr","") or "")).strip()
        for f in vf_primary_flags(txt,limit=5):
            vf_add_answer(cands,f,"visual_ocr_qr:"+str(p.get("name","")),"OCR/QR",int(p.get("score",0)//4)+100)
        for line in txt.splitlines()[:35]:
            line=line.strip()
            if 3<=len(line)<=180:
                vf_add_answer(cands,line,"visual_ocr:"+str(p.get("name","")),"OCR text",int(p.get("score",0)//8)+30+hint_bonus)
    for a in report.get("artifacts",[])[:140]:
        p=Path(a.get("path",""))
        try:
            if not p.exists() or not p.is_file() or p.stat().st_size>=750000: continue
            if not (p.suffix.lower() in [".txt",".json",".log",".md",".csv",".xml"] or any(x in p.name.lower() for x in ["ocr","decoded","answer","secret","key","brief","strings","fallback","constants","chain","decompressed"])):
                continue
            txt=p.read_text(encoding="utf-8",errors="ignore")[:12000]
            for f in vf_primary_flags(txt,limit=6):
                vf_add_answer(cands,f,"artifact:"+a.get("kind",""),"artifact text",int(a.get("score",0)//3)+95)
            for line in txt.splitlines()[:120]:
                line=line.strip(); low=line.lower()
                if 3<=len(line)<=240 and any(k in low for k in markers):
                    vf_add_answer(cands,line,"artifact_context:"+a.get("kind",""),"answer-like artifact line",int(a.get("score",0)//5)+45+hint_bonus)
                    m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|slaptazodis|password|pass|code|kodas|token|login|vartotojas|user|username)\s*[:=]\s*(.+)$",line,re.I)
                    if m: vf_add_answer(cands,m.group(1).strip(),"artifact_value:"+a.get("kind",""),"value after marker",int(a.get("score",0)//5)+85+hint_bonus)
        except Exception:
            pass
    out=[]; seen=set()
    for x in sorted(cands,key=lambda z:z.get("score",0),reverse=True):
        k=x.get("value","").lower()
        if k and k not in seen:
            seen.add(k); out.append(x)
    return out[:220]
def vf_postprocess(report, root):
    if report.get("kind")=="image":
        has_vf=bool(report.get("_visualforge_done")) or any("VisualForge" in str(a.get("source","")) or "FlowForge" in str(a.get("source","")) for a in report.get("artifacts",[]))
        if not has_vf:
            arts, previews = vf_visual_lab(Path(report.get("path","")), root, report)
            existing=set(a.get("path") for a in report.get("artifacts",[]))
            for a in arts:
                if a.get("path") not in existing:
                    report.setdefault("artifacts",[]).append(a); existing.add(a.get("path"))
            report.setdefault("previews",[]).extend(previews)
            report["_visualforge_done"]=True
    # FlowForge extra chain and child pass before final answers.
    text=dp_collect_text(report)[:50000] if "dp_collect_text" in globals() else "\n".join(report.get("strings",[]))
    extra=ff_extra_decoders(text)
    if extra:
        old=set((c.get("type"),(c.get("output","") or "")[:240]) for c in report.get("chain_results",[]))
        for c in extra:
            k=(c.get("type"),(c.get("output","") or "")[:240])
            if k not in old:
                old.add(k); report.setdefault("chain_results",[]).insert(0,c)
                for f in c.get("flags",[]) or []:
                    if f not in report.setdefault("flags",[]): report["flags"].append(f)
        report["chain_results"]=sorted(report.get("chain_results",[]),key=lambda x:x.get("score",0),reverse=True)[:280]
    try:
        ff_child_artifact_autopass(root, report)
    except Exception:
        pass
    try:
        smartsolve_postprocess(report, root)
    except Exception:
        try: stableworkbench_apply_report_postprocess(report, root)
        except Exception: pass
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    report["autopilot_review"]=ff_autopilot_review(report)
    return report
