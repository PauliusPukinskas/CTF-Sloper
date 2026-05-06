# Auto-split from sloper_legacy_monolith.py lines 2652-...
async def run_recipe_endpoint(path:str=Form(...)):
    p=Path(path)
    if not p.exists():
        return {"ok":False,"error":"file not found"}
    try:
        data=readbytes(p)
        fileout=run(["file",str(p)],8).get("out","") if exists("file") else ""
        kind=detect_kind(p,fileout)
        ss=py_strings(data)
        temp={"id":"manual","name":p.name,"path":str(p),"rel":p.name,"size":p.stat().st_size,"entropy":entropy(data[:2_000_000]),"kind":kind,"file":fileout,"fingerprint":{"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest()},"flags":[],"strings":ss[:900],"outputs":[],"previews":[],"commands":[],"extracted":[],"expert_contexts":[],"decoders":[],"chain_results":[],"intermediate_files":[],"findings":[],"next_steps":[],"hypotheses":[],"structured_clues":[],"agent_runs":[],"agent_files":[],"transformations":[],"verifyloop":{},"verified_flags":[],"promoted_children":[],"artifacts":[],"recipe_runs":[],"artifact_graph":{},"candidate_health":{}}
        if kind=="image":
            pv,outs=image_lab(p,p.parent)
            temp["previews"]+=pv; temp["outputs"]+=outs
        temp["verifyloop"]=verifyloop_run_tools("manual",p,temp,p.parent)
        verifyloop_refresh_analysis(temp,data)
        temp["transformations"]=execute_transform_agents(temp,p.parent,data)
        temp["intermediate_files"]=(temp.get("intermediate_files",[])+temp.get("transformations",[]))[:320]
        temp["agent_runs"],temp["agent_files"]=run_agent_forge(temp,p.parent)
        verifyloop_scan_transform_files(temp)
        verifyloop_refresh_analysis(temp,data)
        apply_verified_flags(temp)
        temp["findings"]=rank_findings(temp)
        temp["next_steps"]=next_steps(temp)
        smartsolve_postprocess(temp,p.parent)
        return {"ok":True,"kind":kind,"recipes":temp.get("recipe_runs",[]),"flags":temp.get("flags",[]),"verified_flags":temp.get("verified_flags_visible",[]),"artifacts":temp.get("artifacts",[])[:220],"artifact_graph":temp.get("artifact_graph",{}),"findings":temp.get("findings",[])[:80]}
    except Exception as e:
        return {"ok":False,"error":str(e)}
def smartsolve_strict_target_flag_ok(flag, meta=None):
    """Promote only clean, plausible final target flags. Weird decode noise stays in chain/artifacts, not Summary."""
    flag = str(flag or "").strip()
    if not flag.lower().startswith("ctf_cs{") or not flag.endswith("}"):
        return False
    if "\n" in flag or "\r" in flag or "\t" in flag:
        return False
    if "�" in flag:
        return False
    inner = flag_inner(flag)
    low_inner = inner.lower()
    if len(inner) < 6 or len(inner) > 96:
        return False
    if any(ord(c) < 32 or ord(c) > 126 for c in inner):
        return False
    if any(w in low_inner for w in SMARTSOLVE_NOISE_WORDS):
        return False
    if "ctf_cs" in low_inner or "flag{" in low_inner:
        return False
    # Strict display-safe flag body: words/digits/underscore/dash/dot/colon only.
    # Other symbol-heavy decodes are kept in Chain, not promoted.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_\-:.]{5,95}", inner):
        return False
    # Avoid very random short mixed fragments without separators.
    if len(inner) < 10 and "_" not in inner and "-" not in inner and "." not in inner and ":" not in inner:
        return False
    return True
def smartsolve_clean_verified_list(report):
    out, seen = [], set()
    for v in sorted(report.get("verified_flags", []), key=lambda x:x.get("score",0), reverse=True):
        flag = (v.get("flag") or "").strip()
        key = flag.lower()
        if not flag or key in seen:
            continue
        seen.add(key)
        if not smartsolve_strict_target_flag_ok(flag, v):
            continue
        if v.get("negative_reasons"):
            continue
        if v.get("status") not in ["confirmed", "likely"]:
            continue
        out.append(v)
    return out[:25]
def stableworkbench_apply_report_postprocess(report, root=None):
    try:
        apply_verified_flags(report)
    except Exception:
        pass
    good=[]
    for v in report.get("verified_flags", []):
        flag=v.get("flag","")
        if v.get("status") in PROMOTED_STATUSES and not v.get("negative_reasons") and smartsolve_strict_target_flag_ok(flag, v):
            good.append(flag)
    report["flags"]=list(dict.fromkeys(good))[:30]
    report["verified_flags_visible"]=smartsolve_clean_verified_list(report)
    cleaned=[]
    for f in report.get("findings", []):
        val=f.get("value","")
        typ=f.get("type","")
        # Hide any exact-looking but strict-invalid ctf_cs candidate from front evidence.
        if str(val).lower().startswith("ctf_cs{") and not smartsolve_strict_target_flag_ok(val):
            continue
        if not is_noisy_candidate_text(val, f.get("why",""), typ):
            cleaned.append(f)
    report["findings"]=sorted(cleaned,key=lambda x:x.get("score",0),reverse=True)[:90]
    report["artifacts"]=stableworkbench_artifacts_for_report(report)
    return report
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
    cleaned = []
    for f in report.get("findings", []):
        val=f.get("value","")
        if str(val).lower().startswith("ctf_cs{") and not smartsolve_strict_target_flag_ok(val):
            continue
        if not is_noisy_candidate_text(val, f.get("why",""), f.get("type","")):
            cleaned.append(f)
    report["findings"] = sorted(cleaned, key=lambda x:x.get("score",0), reverse=True)[:90]
    return report
def dp_is_mostly_printable(s):
    s = str(s or "")
    if not s:
        return False
    good = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return good / max(1, len(s)) > 0.88
def dp_flag_score(flag):
    flag = str(flag or "")
    if not flag.lower().startswith("ctf_cs{") or not flag.endswith("}"):
        return -100
    inner = flag_inner(flag)
    score = 0
    if 8 <= len(inner) <= 80: score += 40
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_\-:.]{6,90}", inner or ""): score += 60
    if "_" in inner or "-" in inner or "." in inner or ":" in inner: score += 20
    if any(w in inner.lower() for w in SMARTSOLVE_NOISE_WORDS): score -= 100
    if any(ord(c) < 32 or ord(c) > 126 for c in inner): score -= 120
    if "ctf_cs" in inner.lower(): score -= 90
    return score
def smartsolve_strict_target_flag_ok(flag, meta=None):
    return dp_flag_score(flag) >= 80
def dp_rot_text(s, r):
    a="abcdefghijklmnopqrstuvwxyz"; A=a.upper()
    return str(s).translate(str.maketrans(a+A,a[r:]+a[:r]+A[r:]+A[:r]))
def dp_try_common_decodes(label, text, max_items=80):
    """Small deep decode engine that chains common transforms without flooding UI."""
    text = str(text or "")[:16000]
    results=[]; seen=set()
    def add(t, inp, out, score_bonus=0):
        if not out:
            return
        out=str(out)[:12000]
        k=(t,out[:300])
        if k in seen:
            return
        seen.add(k)
        flags=fast_flag_matches(out, limit=8, scan_limit=12000) if "fast_flag_matches" in globals() else FLAG_TEXT_RE.findall(out)
        sc=score_text(out)+score_bonus+(120 if flags else 0)
        if sc >= 35 or flags:
            results.append({"type":"deeppattern:"+t,"input":str(inp)[:220],"output":out,"flags":flags,"score":sc,"chain_source":label})
    # Start with base decode candidates.
    for item in decode_candidates(text,b"")[:60]:
        add(item.get("type","decode"), item.get("input",""), item.get("output",""), item.get("score",0)//8)
        # second layer on compact outputs
        out=item.get("output","")
        if out and len(out) < 6000 and any(x in out for x in ["=", "{", "}", "ctf", "flag"]) or (out and re.search(r"[A-Za-z0-9+/=_-]{12,}", out)):
            for sub in decode_candidates(out,b"")[:16]:
                add(item.get("type","")+"->"+sub.get("type",""), sub.get("input",""), sub.get("output",""), sub.get("score",0)//7 + 20)
    # ROT then decode for Caesar-hid base64.
    for r in range(1,26):
        rot = dp_rot_text(text[:5000], r)
        if "ctf" in rot.lower() or re.search(r"[A-Za-z0-9+/=_-]{12,}", rot):
            add(f"rot{r}", text[:80], rot, 5)
            for sub in decode_candidates(rot,b"")[:10]:
                add(f"rot{r}->"+sub.get("type",""), sub.get("input",""), sub.get("output",""), sub.get("score",0)//7 + 25)
    return sorted(results,key=lambda x:x.get("score",0),reverse=True)[:max_items]
def dp_xor_key_from_crib(data, crib=b"ctf_cs{", max_key_len=16):
    """Recover repeating XOR key guesses by assuming crib appears at early offsets."""
    data = bytes(data or b"")[:120000]
    outs=[]
    if len(data) < len(crib):
        return outs
    seen=set()
    for off in range(0, min(len(data)-len(crib), 512)):
        key_material=bytes(data[off+i]^crib[i] for i in range(len(crib)))
        for kl in range(1, min(max_key_len, len(key_material))+1):
            key=key_material[:kl]
            if key in seen:
                continue
            seen.add(key)
            dec=bytes(b ^ key[i%len(key)] for i,b in enumerate(data[:60000]))
            txt=dec.decode("utf-8","replace")
            flags=fast_flag_matches(txt, limit=8, scan_limit=60000)
            sc=score_text(txt)+(160 if flags else 0)
            if flags or sc>115:
                outs.append({"type":"deeppattern_xor_crib","key_hex":key.hex(),"key_text":key.decode("utf-8","replace"),"output":txt[:12000],"flags":flags,"score":sc})
    return sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:40]
def dp_jwt_decode(text):
    outs=[]
    for tok in re.findall(r"eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.?[A-Za-z0-9_=-]*", str(text or "")):
        parts=tok.split(".")
        decoded={}
        for idx,name in enumerate(["header","payload","signature"]):
            if idx>=len(parts): continue
            try:
                raw=parts[idx]+"="*((4-len(parts[idx])%4)%4)
                if idx<2:
                    decoded[name]=base64.urlsafe_b64decode(raw.encode()).decode("utf-8","replace")
                else:
                    decoded[name]=parts[idx]
            except Exception as e:
                decoded[name]="decode_error:"+str(e)
        out=json.dumps(decoded,ensure_ascii=False,indent=2)
        outs.append({"type":"deeppattern_jwt_decode","input":tok[:220],"output":out,"flags":fast_flag_matches(out),"score":score_text(out)+80})
    return outs[:30]
def dp_collect_text(report):
    chunks=[]
    chunks += report.get("strings",[])[:1200]
    for o in report.get("outputs",[])[:80]:
        if o.get("ok") is False and "not installed" in (o.get("out","").lower()):
            continue
        chunks.append((o.get("out") or "")[:8000])
    for c in report.get("chain_results",[])[:80]:
        chunks.append((c.get("output") or "")[:5000])
    for a in report.get("artifacts",[])[:80]:
        p=Path(a.get("path",""))
        try:
            if p.exists() and p.is_file() and p.stat().st_size <= 750000 and (p.suffix.lower() in [".txt",".json",".log",".csv",".xml",".html",".md"] or any(x in p.name.lower() for x in ["decoded","strings","stream","rsa","jwt","hash","brief"])):
                chunks.append(p.read_text(encoding="utf-8",errors="ignore")[:8000])
        except Exception:
            pass
    return "\n".join(chunks)[:60000]
def dp_write_artifact(root, report, name, content, kind="deeppattern", score=80):
    outdir=root/"generated"/"deeppattern"/safe(report.get("name","file"))
    outdir.mkdir(parents=True,exist_ok=True)
    p=outdir/safe(name)
    try:
        p.write_text(str(content), encoding="utf-8", errors="ignore")
        return {"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"DeepPattern","score":score,"note":"DeepPattern generated artifact","exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
    except Exception:
        return None
def dp_lsb_bit_order_variants(path, root, report):
    """Extract more PNG/image LSB bit ordering variants and save candidate texts."""
    out=[]
    try:
        im=Image.open(path).convert("RGB")
        arr=np.array(im)
        base=root/"generated"/"deeppattern"/safe(report.get("name","file"))/"lsb_variants"
        base.mkdir(parents=True,exist_ok=True)
        orders=["RGB","RBG","GRB","GBR","BRG","BGR"]
        bit_orders=[("msb_byte", False), ("lsb_byte", True)]
        channels={"R":[0],"G":[1],"B":[2],"RG":[0,1],"GB":[1,2],"RB":[0,2],"RGB":[0,1,2],"BGR":[2,1,0]}
        made=0
        for cname,idxs in channels.items():
            bits=[]
            for pix in arr.reshape(-1,3)[:900000]:
                for idx in idxs:
                    bits.append(int(pix[idx]&1))
            for boname,rev in bit_orders:
                bs=[]
                for i in range(0,len(bits)-7,8):
                    chunk=bits[i:i+8]
                    if rev: chunk=chunk[::-1]
                    val=0
                    for b in chunk:
                        val=(val<<1)|b
                    bs.append(val)
                txt=bytes(bs).decode("utf-8","replace")
                if "ctf_cs" in txt.lower() or score_text(txt)>85:
                    p=base/f"lsb_{cname}_{boname}.txt"
                    p.write_text(txt[:120000],encoding="utf-8",errors="ignore")
                    out.append({"kind":"lsb_variant","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"DeepPattern LSB variants","score":score_text(txt),"note":f"LSB {cname} {boname} extraction","exists":True,"size":p.stat().st_size,"file":report.get("rel","")})
                    made+=1
                    if made>=24:
                        break
            if made>=24:
                break
    except Exception:
        pass
    return out
def deeppattern_enhance(report, root, data):
    """Harder-pattern pass: deep chains, XOR crib, JWT, recipe reinforcement."""
    text=dp_collect_text(report)
    extra_chain=[]
    extra_chain += dp_try_common_decodes("DeepPattern collected text", text, 100)
    for x in dp_xor_key_from_crib(data):
        extra_chain.append({"type":x["type"],"input":x.get("key_hex",""),"output":x["output"],"flags":x.get("flags",[]),"score":x.get("score",0),"chain_source":"DeepPattern XOR crib key="+x.get("key_text","")})
    extra_chain += dp_jwt_decode(text)
    # Dedupe into chain_results.
    seen=set((c.get("type"),(c.get("output","") or "")[:260]) for c in report.get("chain_results",[]))
    for c in sorted(extra_chain,key=lambda x:x.get("score",0),reverse=True):
        k=(c.get("type"),(c.get("output","") or "")[:260])
        if k not in seen:
            seen.add(k)
            report.setdefault("chain_results",[]).insert(0,c)
    report["chain_results"]=sorted(report.get("chain_results",[]),key=lambda x:x.get("score",0),reverse=True)[:260]
    # Artifacts for top deep outputs.
    for i,c in enumerate(report.get("chain_results",[])[:35]):
        if str(c.get("type","")).startswith("deeppattern") and c.get("score",0)>85:
            art=dp_write_artifact(root, report, f"deeppattern_chain_{i:02d}_{safe(c.get('type','out'))}.txt", c.get("output",""), "deeppattern_chain", c.get("score",0))
            if art:
                report.setdefault("artifacts",[]).insert(0,art)
                report.setdefault("transformations",[]).append(art)
    # Extra image LSB variants.
    if report.get("kind")=="image":
        arts=dp_lsb_bit_order_variants(Path(report.get("path","")), root, report)
        report.setdefault("artifacts",[]).extend(arts)
        report.setdefault("transformations",[]).extend(arts)
        for art in arts:
            try:
                txt=Path(art["path"]).read_text(encoding="utf-8",errors="ignore")[:20000]
                for f in fast_flag_matches(txt,limit=8):
                    if f not in report.setdefault("flags",[]):
                        report["flags"].append(f)
            except Exception:
                pass
    # Structured artifacts for JWT/RSA.
    clues=detect_structured_clues(text) if "detect_structured_clues" in globals() else []
    rsa=[c for c in clues if str(c.get("type","")).startswith("rsa_parameter")]
    jwt=[c for c in clues if c.get("type")=="jwt_token"]
    if rsa:
        art=dp_write_artifact(root, report, "deeppattern_rsa_params.json", json.dumps(rsa,ensure_ascii=False,indent=2), "deeppattern_rsa", 92)
        if art: report.setdefault("artifacts",[]).insert(0,art)
    if jwt:
        art=dp_write_artifact(root, report, "deeppattern_jwt_candidates.json", json.dumps(jwt,ensure_ascii=False,indent=2), "deeppattern_jwt", 88)
        if art: report.setdefault("artifacts",[]).insert(0,art)
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
                if f not in rep["flags"]: rep["flags"].append(f)
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
        for mf in fast_flag_matches(r.get("out",""), limit=20):
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
    deeppattern_enhance(rep,root,data)
    apply_verified_flags(rep)
    verifyloop_promote_artifacts(root,rep)
    rep["findings"]=rank_findings(rep)
    rep["next_steps"]=next_steps(rep)
    smartsolve_postprocess(rep,root)
    return rep
def dp_recursive_deep_decode(seed_label, seed_text, max_depth=5, beam=26):
    """Beam-search common CTF encoding stacks: base64/hex/base32/url/rot/reverse/etc."""
    seed_text = str(seed_text or "")[:18000]
    results = []
    frontier = [{"label": seed_label, "text": seed_text, "path": seed_label, "score": score_text(seed_text)}]
    seen_text = set()
    for depth in range(max_depth):
        next_frontier = []
        for node in frontier[:beam]:
            txt = node["text"][:14000]
            key = txt[:500]
            if key in seen_text:
                continue
            seen_text.add(key)
            # Normal decoders.
            for item in decode_candidates(txt, b"")[:60]:
                out = str(item.get("output",""))[:14000]
                if not out:
                    continue
                path = node["path"] + " -> " + item.get("type","decode")
                flags = fast_flag_matches(out, limit=10, scan_limit=14000)
                sc = score_text(out) + item.get("score",0)//4 + depth*20 + (220 if flags else 0)
                rec = {"type":"deeppattern_recursive","input":item.get("input",""),"output":out,"flags":flags,"score":sc,"chain_source":path}
                results.append(rec)
                # Keep useful / likely encoded outputs in beam.
                if len(out) <= 12000 and (flags or score_text(out) > 35 or re.search(r"[A-Za-z0-9+/=_-]{12,}", out) or re.search(r"[A-Fa-f0-9]{16,}", out)):
                    next_frontier.append({"label":item.get("type","decode"),"text":out,"path":path,"score":sc})
            # ROT branch on compact text.
            if len(txt) <= 6000:
                for r in range(1,26):
                    rot = dp_rot_text(txt, r)
                    if "ctf_cs" in rot.lower() or re.search(r"[A-Za-z0-9+/=_-]{12,}", rot):
                        flags = fast_flag_matches(rot, limit=10, scan_limit=8000)
                        sc = score_text(rot) + (180 if flags else 0) + depth*15
                        path = node["path"] + f" -> rot{r}"
                        results.append({"type":"deeppattern_recursive_rot","input":txt[:180],"output":rot[:12000],"flags":flags,"score":sc,"chain_source":path})
                        next_frontier.append({"label":f"rot{r}","text":rot[:12000],"path":path,"score":sc})
        # de-dupe frontier by prefix, keep best
        dedup = {}
        for n in next_frontier:
            k = n["text"][:300]
            if k not in dedup or n["score"] > dedup[k]["score"]:
                dedup[k] = n
        frontier = sorted(dedup.values(), key=lambda x:x["score"], reverse=True)[:beam]
        if not frontier:
            break
    # Dedupe results.
    out = []
    seen = set()
    for r in sorted(results, key=lambda x:x.get("score",0), reverse=True):
        k = (r.get("chain_source",""), (r.get("output","") or "")[:320])
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out[:160]
def deeppattern_enhance(report, root, data):
    """Harder-pattern pass: deep recursive chains, XOR crib, JWT, RSA/JWT artifacts, LSB variants."""
    text = dp_collect_text(report)
    extra_chain = []
    extra_chain += dp_recursive_deep_decode("DeepPattern collected text", text, max_depth=5, beam=24)
    # Also decode each high-signal string/blob separately to avoid one huge text swallowing tokens.
    for s in report.get("strings", [])[:200]:
        if any(x in s.lower() for x in ["ctf", "flag", "eyj", "rsa", "base", "xor"]) or re.search(r"[A-Za-z0-9+/=_-]{16,}|[A-Fa-f0-9]{20,}", s):
            extra_chain += dp_recursive_deep_decode("DeepPattern string", s, max_depth=5, beam=14)[:30]
    for x in dp_xor_key_from_crib(data):
        extra_chain.append({"type":x["type"],"input":x.get("key_hex",""),"output":x["output"],"flags":x.get("flags",[]),"score":x.get("score",0),"chain_source":"DeepPattern XOR crib key="+x.get("key_text","")})
    extra_chain += dp_jwt_decode(text)
    seen=set((c.get("type"),(c.get("output","") or "")[:260]) for c in report.get("chain_results",[]))
    for c in sorted(extra_chain,key=lambda x:x.get("score",0),reverse=True):
        k=(c.get("type"),(c.get("output","") or "")[:260])
        if k not in seen:
            seen.add(k)
            report.setdefault("chain_results",[]).insert(0,c)
            # capture exact flags immediately
            for f in c.get("flags",[]) or []:
                if f not in report.setdefault("flags",[]):
                    report["flags"].append(f)
    report["chain_results"]=sorted(report.get("chain_results",[]),key=lambda x:x.get("score",0),reverse=True)[:320]
    for i,c in enumerate(report.get("chain_results",[])[:50]):
        if str(c.get("type","")).startswith("deeppattern") and c.get("score",0)>85:
            art=dp_write_artifact(root, report, f"deeppattern_chain_{i:02d}_{safe(c.get('type','out'))}.txt", c.get("output",""), "deeppattern_chain", c.get("score",0))
            if art:
                report.setdefault("artifacts",[]).insert(0,art)
                report.setdefault("transformations",[]).append(art)
    if report.get("kind")=="image":
        arts=dp_lsb_bit_order_variants(Path(report.get("path","")), root, report)
        report.setdefault("artifacts",[]).extend(arts)
        report.setdefault("transformations",[]).extend(arts)
        for art in arts:
            try:
                txt=Path(art["path"]).read_text(encoding="utf-8",errors="ignore")[:20000]
                for f in fast_flag_matches(txt,limit=8):
                    if f not in report.setdefault("flags",[]):
                        report["flags"].append(f)
            except Exception:
                pass
    clues=detect_structured_clues(text) if "detect_structured_clues" in globals() else []
    rsa=[c for c in clues if str(c.get("type","")).startswith("rsa_parameter")]
    jwt=[c for c in clues if c.get("type")=="jwt_token"]
    if rsa:
        art=dp_write_artifact(root, report, "deeppattern_rsa_params.json", json.dumps(rsa,ensure_ascii=False,indent=2), "deeppattern_rsa", 92)
        if art: report.setdefault("artifacts",[]).insert(0,art)
    if jwt:
        art=dp_write_artifact(root, report, "deeppattern_jwt_candidates.json", json.dumps(jwt,ensure_ascii=False,indent=2), "deeppattern_jwt", 88)
        if art: report.setdefault("artifacts",[]).insert(0,art)
    return report
def dp_extract_decode_seeds(text):
    text = str(text or "")[:24000]
    seeds = []
    def add(label, value):
        value = str(value or "").strip().strip("'\"`")
        if len(value) >= 8 and value not in [v for _,v in seeds]:
            seeds.append((label, value[:16000]))
    add("full_text", text)
    # key=value / key: value formats common in CTF statements and files.
    for m in re.finditer(r"\b[A-Za-z0-9_.-]{1,40}\s*[:=]\s*([A-Za-z0-9+/=_-]{12,})", text):
        add("key_value_blob", m.group(1))
    # Long base/hex tokens, but strip obvious prefixes/suffixes.
    for m in re.finditer(r"[A-Za-z0-9+/=_-]{12,}", text):
        tok = m.group(0).strip()
        if "=" in tok and not tok.endswith("="):
            # blob=AAAA or data:AAAA may have been swallowed by the permissive regex.
            parts = tok.split("=")
            for part in parts:
                if len(part) >= 12:
                    add("split_equals_blob", part)
        add("long_token", tok)
    for m in re.finditer(r"\b[A-Fa-f0-9]{16,}\b", text):
        add("hex_token", m.group(0))
    return seeds[:120]
def dp_recursive_deep_decode(seed_label, seed_text, max_depth=5, beam=26):
    """Beam-search common CTF encoding stacks with key=value token extraction."""
    seed_text = str(seed_text or "")[:24000]
    results = []
    frontier = []
    for label, value in dp_extract_decode_seeds(seed_text):
        frontier.append({"label": label, "text": value, "path": seed_label + ":" + label, "score": score_text(value)})
    seen_text = set()
    for depth in range(max_depth):
        next_frontier = []
        for node in frontier[:beam]:
            txt = node["text"][:14000]
            key = txt[:500]
            if key in seen_text:
                continue
            seen_text.add(key)
            # Expand extracted tokens at every level too.
            local_inputs = [(node["label"], txt)]
            if depth < max_depth - 1:
                local_inputs += dp_extract_decode_seeds(txt)[1:30]
            for local_label, local_txt in local_inputs[:30]:
                for item in decode_candidates(local_txt, b"")[:60]:
                    out = str(item.get("output",""))[:14000]
                    if not out:
                        continue
                    path = node["path"] + " -> " + local_label + " -> " + item.get("type","decode")
                    flags = fast_flag_matches(out, limit=10, scan_limit=14000)
                    sc = score_text(out) + item.get("score",0)//4 + depth*20 + (220 if flags else 0)
                    rec = {"type":"deeppattern_recursive","input":item.get("input",""),"output":out,"flags":flags,"score":sc,"chain_source":path}
                    results.append(rec)
                    if len(out) <= 12000 and (flags or score_text(out) > 35 or re.search(r"[A-Za-z0-9+/=_-]{12,}", out) or re.search(r"[A-Fa-f0-9]{16,}", out)):
                        next_frontier.append({"label":item.get("type","decode"),"text":out,"path":path,"score":sc})
                # ROT branch on compact local text.
                if len(local_txt) <= 6000:
                    for r in range(1,26):
                        rot = dp_rot_text(local_txt, r)
                        if "ctf_cs" in rot.lower() or re.search(r"[A-Za-z0-9+/=_-]{12,}", rot):
                            flags = fast_flag_matches(rot, limit=10, scan_limit=8000)
                            sc = score_text(rot) + (180 if flags else 0) + depth*15
                            path = node["path"] + f" -> {local_label} -> rot{r}"
                            results.append({"type":"deeppattern_recursive_rot","input":local_txt[:180],"output":rot[:12000],"flags":flags,"score":sc,"chain_source":path})
                            next_frontier.append({"label":f"rot{r}","text":rot[:12000],"path":path,"score":sc})
        dedup = {}
        for n in next_frontier:
            k = n["text"][:300]
            if k not in dedup or n["score"] > dedup[k]["score"]:
                dedup[k] = n
        frontier = sorted(dedup.values(), key=lambda x:x["score"], reverse=True)[:beam]
        if not frontier:
            break
    out = []
    seen = set()
    for r in sorted(results, key=lambda x:x.get("score",0), reverse=True):
        k = (r.get("chain_source",""), (r.get("output","") or "")[:320])
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out[:180]
def dp_ascii_from_bytes(b):
    try:
        s = bytes(b).decode("utf-8", "replace")
        if dp_is_mostly_printable(s):
            return s
        return s
    except Exception:
        return ""
def dp_basic_transforms(s):
    """Return possible one-step transforms without score gating."""
    s = str(s or "").strip()
    outs = []
    def add(name, out):
        if out:
            outs.append((name, str(out)[:16000]))
    compact = re.sub(r"\s+", "", s)
    # Strip key=value leftovers defensively.
    if "=" in compact and not compact.endswith("="):
        for part in compact.split("="):
            if len(part) >= 8:
                add("split_equals", part)
    # URL/html.
    try:
        u = urllib.parse.unquote(s)
        if u != s: add("url_decode", u)
    except Exception: pass
    try:
        h = html.unescape(s)
        if h != s: add("html_unescape", h)
    except Exception: pass
    # base64 / urlsafe
    try:
        if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}", compact) and len(compact) <= 12000:
            padded = compact + "="*((4-len(compact)%4)%4)
            add("base64", base64.b64decode(padded, validate=False).decode("utf-8","replace"))
            add("base64_urlsafe", base64.urlsafe_b64decode(padded).decode("utf-8","replace"))
    except Exception: pass
    # hex
    try:
        if len(compact) % 2 == 0 and len(compact) <= 20000 and re.fullmatch(r"[A-Fa-f0-9]{8,}", compact):
            add("hex", bytes.fromhex(compact).decode("utf-8","replace"))
    except Exception: pass
    # base32
    try:
        if re.fullmatch(r"[A-Z2-7=]{8,}", compact) and len(compact) <= 12000:
            add("base32", base64.b32decode(compact + "="*((8-len(compact)%8)%8)).decode("utf-8","replace"))
    except Exception: pass
    # reverse and ROT on compact strings only
    if len(s) <= 6000:
        add("reverse", s[::-1])
        for r in range(1,26):
            rot = dp_rot_text(s, r)
            if "ctf" in rot.lower() or re.search(r"[A-Za-z0-9+/=_-]{12,}|[A-Fa-f0-9]{16,}", rot):
                add(f"rot{r}", rot)
    return outs
def dp_raw_transform_bfs(label, text, max_depth=6, beam=80):
    seeds = dp_extract_decode_seeds(text)
    queue = [{"text":v, "path":label+":"+k, "depth":0, "score":score_text(v)} for k,v in seeds]
    results = []
    seen = set()
    while queue and len(results) < 260:
        queue = sorted(queue, key=lambda x:x.get("score",0), reverse=True)[:beam]
        cur = queue.pop(0)
        txt = cur["text"][:16000]
        key = txt[:500]
        if (cur["depth"], key) in seen:
            continue
        seen.add((cur["depth"], key))
        flags = fast_flag_matches(txt, limit=10, scan_limit=16000)
        if flags:
            results.append({"type":"deeppattern_raw_bfs","input":cur["path"],"output":txt,"flags":flags,"score":score_text(txt)+300-cur["depth"]*5,"chain_source":cur["path"]})
        if cur["depth"] >= max_depth:
            continue
        for name,out in dp_basic_transforms(txt):
            if not out or out == txt:
                continue
            sc = score_text(out)
            # Keep intermediates that are printable or look encoded.
            if fast_flag_matches(out, limit=1) or dp_is_mostly_printable(out) or re.search(r"[A-Za-z0-9+/=_-]{12,}|[A-Fa-f0-9]{16,}", out):
                queue.append({"text":out[:16000],"path":cur["path"]+" -> "+name,"depth":cur["depth"]+1,"score":sc + (200 if "ctf_cs" in out.lower() else 0)})
    # Add final high-scoring non-flag outputs too.
    out = []
    seen2 = set()
    for r in sorted(results, key=lambda x:x.get("score",0), reverse=True):
        k=(r.get("chain_source",""), r.get("output","")[:300])
        if k not in seen2:
            seen2.add(k)
            out.append(r)
    return out[:120]
def deeppattern_enhance(report, root, data):
    """Harder-pattern pass: raw BFS chains, recursive decode, XOR crib, JWT, RSA/JWT artifacts, LSB variants."""
    text = dp_collect_text(report)
    extra_chain = []
    extra_chain += dp_raw_transform_bfs("DeepPattern raw BFS", text, max_depth=6, beam=80)
    extra_chain += dp_recursive_deep_decode("DeepPattern collected text", text, max_depth=5, beam=24)
    for s in report.get("strings", [])[:220]:
        if any(x in s.lower() for x in ["ctf", "flag", "eyj", "rsa", "base", "xor"]) or re.search(r"[A-Za-z0-9+/=_-]{16,}|[A-Fa-f0-9]{20,}", s):
            extra_chain += dp_raw_transform_bfs("DeepPattern string", s, max_depth=6, beam=40)[:40]
            extra_chain += dp_recursive_deep_decode("DeepPattern string", s, max_depth=5, beam=14)[:30]
    for x in dp_xor_key_from_crib(data):
        extra_chain.append({"type":x["type"],"input":x.get("key_hex",""),"output":x["output"],"flags":x.get("flags",[]),"score":x.get("score",0),"chain_source":"DeepPattern XOR crib key="+x.get("key_text","")})
    extra_chain += dp_jwt_decode(text)
    seen=set((c.get("type"),(c.get("output","") or "")[:260]) for c in report.get("chain_results",[]))
    for c in sorted(extra_chain,key=lambda x:x.get("score",0),reverse=True):
        k=(c.get("type"),(c.get("output","") or "")[:260])
        if k not in seen:
            seen.add(k)
            report.setdefault("chain_results",[]).insert(0,c)
            for f in c.get("flags",[]) or []:
                if f not in report.setdefault("flags",[]):
                    report["flags"].append(f)
    report["chain_results"]=sorted(report.get("chain_results",[]),key=lambda x:x.get("score",0),reverse=True)[:340]
    for i,c in enumerate(report.get("chain_results",[])[:55]):
        if str(c.get("type","")).startswith("deeppattern") and c.get("score",0)>85:
            art=dp_write_artifact(root, report, f"deeppattern_chain_{i:02d}_{safe(c.get('type','out'))}.txt", c.get("output",""), "deeppattern_chain", c.get("score",0))
            if art:
                report.setdefault("artifacts",[]).insert(0,art)
                report.setdefault("transformations",[]).append(art)
    if report.get("kind")=="image":
        arts=dp_lsb_bit_order_variants(Path(report.get("path","")), root, report)
        report.setdefault("artifacts",[]).extend(arts)
        report.setdefault("transformations",[]).extend(arts)
        for art in arts:
            try:
                txt=Path(art["path"]).read_text(encoding="utf-8",errors="ignore")[:20000]
                for f in fast_flag_matches(txt,limit=8):
                    if f not in report.setdefault("flags",[]):
                        report["flags"].append(f)
            except Exception:
                pass
    clues=detect_structured_clues(text) if "detect_structured_clues" in globals() else []
    rsa=[c for c in clues if str(c.get("type","")).startswith("rsa_parameter")]
    jwt=[c for c in clues if c.get("type")=="jwt_token"]
    if rsa:
        art=dp_write_artifact(root, report, "deeppattern_rsa_params.json", json.dumps(rsa,ensure_ascii=False,indent=2), "deeppattern_rsa", 92)
        if art: report.setdefault("artifacts",[]).insert(0,art)
    if jwt:
        art=dp_write_artifact(root, report, "deeppattern_jwt_candidates.json", json.dumps(jwt,ensure_ascii=False,indent=2), "deeppattern_jwt", 88)
        if art: report.setdefault("artifacts",[]).insert(0,art)
    return report
def dp_basic_transforms_structural(s, include_rot=False):
    s = str(s or "").strip()
    outs = []
    seen = set()
    def add(name, out):
        out = str(out or "")[:16000]
        if out and out != s and (name, out[:300]) not in seen:
            seen.add((name, out[:300]))
            outs.append((name, out))
    compact = re.sub(r"\s+", "", s)
    if "=" in compact and not compact.endswith("="):
        for part in compact.split("="):
            if len(part) >= 8:
                add("split_equals", part)
    try:
        u = urllib.parse.unquote(s)
        if u != s: add("url_decode", u)
    except Exception: pass
    try:
        h = html.unescape(s)
        if h != s: add("html_unescape", h)
    except Exception: pass
    try:
        if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}", compact) and len(compact) <= 12000:
            padded = compact + "="*((4-len(compact)%4)%4)
            add("base64", base64.b64decode(padded, validate=False).decode("utf-8","replace"))
            add("base64_urlsafe", base64.urlsafe_b64decode(padded).decode("utf-8","replace"))
    except Exception: pass
    try:
        if len(compact) % 2 == 0 and len(compact) <= 20000 and re.fullmatch(r"[A-Fa-f0-9]{8,}", compact):
            add("hex", bytes.fromhex(compact).decode("utf-8","replace"))
    except Exception: pass
    try:
        if re.fullmatch(r"[A-Z2-7=]{8,}", compact) and len(compact) <= 12000:
            add("base32", base64.b32decode(compact + "="*((8-len(compact)%8)%8)).decode("utf-8","replace"))
    except Exception: pass
    if len(s) <= 6000:
        add("reverse", s[::-1])
    if include_rot and len(s) <= 5000:
        for r in range(1,26):
            rot = dp_rot_text(s, r)
            if "ctf" in rot.lower() or re.search(r"[A-Za-z0-9+/=_-]{12,}|[A-Fa-f0-9]{16,}", rot):
                add(f"rot{r}", rot)
    return outs
def dp_raw_transform_bfs(label, text, max_depth=6, beam=80):
    """Deterministic BFS for encoding stacks. Does not let ROT noise evict base/hex paths."""
    from collections import deque
    seeds = dp_extract_decode_seeds(text)
    q = deque()
    for k,v in seeds:
        q.append({"text":v, "path":label+":"+k, "depth":0})
    results = []
    seen = set()
    states = 0
    while q and states < 2500 and len(results) < 260:
        cur = q.popleft()
        states += 1
        txt = cur["text"][:16000]
        key = (cur["depth"], txt[:500])
        if key in seen:
            continue
        seen.add(key)
        flags = fast_flag_matches(txt, limit=10, scan_limit=16000)
        if flags:
            results.append({"type":"deeppattern_raw_bfs","input":cur["path"],"output":txt,"flags":flags,"score":score_text(txt)+350-cur["depth"]*10,"chain_source":cur["path"]})
        if cur["depth"] >= max_depth:
            continue
        include_rot = cur["depth"] <= 1
        # Structural transforms first.
        for name,out in dp_basic_transforms_structural(txt, include_rot=False):
            if not out:
                continue
            # keep if printable OR encoded-like OR flag-like
            if fast_flag_matches(out, limit=1) or dp_is_mostly_printable(out) or re.search(r"[A-Za-z0-9+/=_-]{12,}|[A-Fa-f0-9]{16,}", out):
                q.append({"text":out[:16000],"path":cur["path"]+" -> "+name,"depth":cur["depth"]+1})
        # ROT after structural, bounded.
        if include_rot:
            for name,out in dp_basic_transforms_structural(txt, include_rot=True):
                if not name.startswith("rot"):
                    continue
                if fast_flag_matches(out, limit=1) or "ctf" in out.lower() or re.search(r"[A-Za-z0-9+/=_-]{12,}", out):
                    q.append({"text":out[:16000],"path":cur["path"]+" -> "+name,"depth":cur["depth"]+1})
    out = []
    seen2 = set()
    for r in sorted(results, key=lambda x:x.get("score",0), reverse=True):
        k=(r.get("chain_source",""), r.get("output","")[:300])
        if k not in seen2:
            seen2.add(k)
            out.append(r)
    return out[:120]
def dp_xor_key_from_crib(data, crib=b"ctf_cs{", max_key_len=24):
    """Recover repeating XOR keys from crib at any file offset with correct key alignment."""
    data = bytes(data or b"")[:160000]
    outs=[]
    if len(data) < len(crib):
        return outs
    seen=set()
    for off in range(0, min(len(data)-len(crib), 4096)):
        for kl in range(1, max_key_len+1):
            key=[None]*kl
            ok=True
            for i,c in enumerate(crib):
                pos=(off+i) % kl
                val=data[off+i]^c
                if key[pos] is not None and key[pos] != val:
                    ok=False
                    break
                key[pos]=val
            if not ok or any(x is None for x in key):
                continue
            keyb=bytes(key)
            if keyb in seen:
                continue
            seen.add(keyb)
            dec=bytes(b ^ keyb[i%len(keyb)] for i,b in enumerate(data[:80000]))
            txt=dec.decode("utf-8","replace")
            flags=fast_flag_matches(txt, limit=10, scan_limit=80000)
            sc=score_text(txt)+(180 if flags else 0)
            # Require either target flag or very readable text.
            if flags or (sc>130 and dp_is_mostly_printable(txt[:2000])):
                outs.append({"type":"deeppattern_xor_crib","key_hex":keyb.hex(),"key_text":keyb.decode("utf-8","replace"),"output":txt[:14000],"flags":flags,"score":sc})
    return sorted(outs,key=lambda x:x.get("score",0),reverse=True)[:60]
