# Auto-split from sloper_legacy_monolith.py lines 6111-...
def project_summary(reports, meta):
    """FlowForge fast aggregation + project-level review."""
    # Use existing lightweight logic, but include helpers/review.
    flags=[]; verified_map={}; kinds={}; evidence=[]; chains=[]; actions=[]; missing=[]; agents=[]; transforms=[]; verifyloops=[]; artifacts=[]; recipes=[]; graphs=[]; answers=[]; wrappers=[]; reviews=[]
    for r in reports:
        kinds[r.get("kind","?")]=kinds.get(r.get("kind","?"),0)+1
        if "answer_candidates" not in r:
            try: r["answer_candidates"]=vf_collect_answer_candidates(r)
            except Exception: r["answer_candidates"]=[]
        if "flag_wrapping_helpers" not in r:
            try: r["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(r)
            except Exception: r["flag_wrapping_helpers"]=[]
        if "autopilot_review" not in r:
            try: r["autopilot_review"]=ff_autopilot_review(r)
            except Exception: r["autopilot_review"]={}
        reviews.append({"file":r.get("rel"),**(r.get("autopilot_review") or {})})
        for v in r.get("verified_flags_visible",[])[:80]:
            key=(v.get("flag") or "").lower(); vv={"file":r.get("rel"),**v}
            if key and (key not in verified_map or vv.get("score",0)>verified_map[key].get("score",0)): verified_map[key]=vv
        for f in r.get("flags",[])[:80]:
            if smartsolve_strict_target_flag_ok(f): flags.append({"file":r.get("rel"),"flag":f,"score":999,"status":"promoted"})
        for ans in r.get("answer_candidates",[])[:80]: answers.append({"file":r.get("rel"),**ans})
        for h in r.get("flag_wrapping_helpers",[])[:40]: wrappers.append({"file":r.get("rel"),**h})
        for f in r.get("findings",[])[:40]:
            if not is_noisy_candidate_text(f.get("value",""),f.get("why",""),f.get("type","")): evidence.append({"file":r.get("rel"),**f})
        for c in r.get("chain_results",[])[:30]:
            out=(c.get("output","") or "")[:900]
            if c.get("score",0)>70 and not is_noisy_candidate_text(out,c.get("type",""),"chain"):
                chains.append({"file":r.get("rel"),"type":c.get("type"),"source":c.get("chain_source"),"score":c.get("score"),"output":out})
        for s in r.get("next_steps",[])[:8]: actions.append({"file":r.get("rel"),**s})
        for a in r.get("agent_runs",[])[:8]: agents.append({"file":r.get("rel"),"kind":r.get("kind"),**a})
        for t in r.get("transformations",[])[:40]: transforms.append({"file":r.get("rel"),**t})
        if r.get("verifyloop"): verifyloops.append({"file":r.get("rel"),"kind":r.get("kind"),**r.get("verifyloop",{})})
        for art in r.get("artifacts",[])[:220]: artifacts.append(art)
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
    flags=sorted(dedupe_by(flags,lambda x:(x.get("flag") or "").lower()),key=lambda x:x.get("score",0),reverse=True)[:80]
    answers=sorted(dedupe_by(answers,lambda x:(x.get("value") or "").lower()),key=lambda x:x.get("score",0),reverse=True)[:220]
    wrappers=sorted(dedupe_by(wrappers,lambda x:(x.get("suggested_flag") or "").lower()),key=lambda x:x.get("score",0),reverse=True)[:80]
    verified_all=sorted(verified_map.values(),key=lambda x:x.get("score",0),reverse=True)[:100]
    evidence=sorted(evidence,key=lambda x:x.get("score",0),reverse=True)[:120]
    chains=sorted(chains,key=lambda x:x.get("score",0) or 0,reverse=True)[:100]
    artifacts=sorted(artifacts,key=lambda x:(x.get("exists",False),x.get("score",0),x.get("size",0)),reverse=True)[:900]
    recipes=sorted(recipes,key=lambda x:x.get("score",0),reverse=True)[:150]
    exact=[f for f in flags if "ctf_cs{" in f.get("flag","").lower()]
    workflow=[]
    if exact: workflow.append({"priority":100,"step":"Submit/check top strict ctf_cs flag.","why":"Primary contest format candidate survived strict filters."})
    elif answers: workflow.append({"priority":97,"step":"Open Answer Candidates and Flag Wrapping Helpers.","why":"No strict flag found; likely answer may need wrapping as ctf_cs{answer}."})
    if reviews: workflow.append({"priority":95,"step":"Open AutoPilot Review.","why":"FlowForge summarized the next best action per file."})
    if recipes: workflow.append({"priority":92,"step":"Open Recipes tab and follow top recipe.","why":"Recipe Engine picked likely solve paths."})
    if artifacts: workflow.append({"priority":90,"step":"Open Artifacts / Visual Lab outputs.","why":"Generated/transformed/extracted files are collected with open/copy controls."})
    priority=sorted([{"file":r.get("rel"),"kind":r.get("kind"),"flags":len(r.get("flags",[])),"answers":len(r.get("answer_candidates",[])),"wrappers":len(r.get("flag_wrapping_helpers",[])),"verified":len(r.get("verified_flags_visible",[])),"recipes":len(r.get("recipe_runs",[])),"artifacts":len(r.get("artifacts",[])),"findings":len(r.get("findings",[])),"chains":len(r.get("chain_results",[])),"top_score":max([x.get("score",0) for x in r.get("findings",[])]+[0])} for r in reports],key=lambda x:(x["flags"],x["answers"],x["verified"],x["recipes"],x["top_score"],x["artifacts"]),reverse=True)[:140]
    summary={"flags":flags,"answer_candidates":answers,"flag_wrapping_helpers":wrappers,"autopilot_reviews":reviews,"verified_flags":verified_all,"exact_flags":exact,"kinds":kinds,"evidence_board":evidence,"top_findings":evidence,"top_chains":chains,"agents":sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:140],"transformations":sorted(transforms,key=lambda x:x.get("score",0),reverse=True)[:240],"artifacts":artifacts,"recipes":recipes,"artifact_graphs":graphs[:120],"verifyloops":verifyloops[:140],"hypotheses":workflowbrain_project_hypotheses(reports) if "workflowbrain_project_hypotheses" in globals() else [],"workflow_steps":sorted(workflow+actions,key=lambda x:x.get("priority",0),reverse=True)[:160],"missing_tools":sorted(set(missing))[:120],"priority_files":priority}
    summary["health"]=cl_project_health(reports, summary) if "cl_project_health" in globals() else {"status":"solved" if flags else ("answer_candidates" if answers else "needs_review")}
    summary["unresolved_plan"]=cl_unresolved_plan(reports) if "cl_unresolved_plan" in globals() else []
    return summary
def mb_gen_cases():
    import base64 as _b64, urllib.parse as _url, gzip as _gzip, zlib as _zlib, bz2 as _bz2, lzma as _lzma
    cases=[]
    def add(name, kind, blob, expected, mode="text"):
        cases.append({"name":name,"kind":kind,"blob":blob,"expected":expected,"mode":mode})
    # 50 encoding stacks
    for i in range(50):
        flag=f"ctf_cs{{ff_enc_{i:02d}_ok}}".encode()
        if i%10==0: blob=_b64.b64encode(flag).decode()
        elif i%10==1: blob=_b64.b64encode(_b64.b64encode(flag)).decode()
        elif i%10==2: blob=_b64.b64encode(flag).decode().encode().hex()
        elif i%10==3: blob=_b64.b64encode(_b64.b64encode(flag).decode().encode().hex().encode()).decode()
        elif i%10==4: blob=_url.quote(_b64.b64encode(flag).decode())
        elif i%10==5: blob=" ".join(str(b) for b in flag)
        elif i%10==6: blob="".join(f"{b:08b}" for b in flag)
        elif i%10==7: blob=_b64.b32encode(flag).decode()
        elif i%10==8:
            # base58 encode
            n=int.from_bytes(flag,"big"); out=""
            while n: n,rem=divmod(n,58); out=B58_ALPHABET[rem]+out
            blob=out
        else: blob=html.escape(_b64.b64encode(flag).decode())
        add(f"encoding_{i:02d}","encoding","blob="+blob,flag.decode())
    # 25 XOR
    for i in range(25):
        flag=f"ctf_cs{{ff_xor_{i:02d}_ok}}".encode()
        key=[b"k",b"xy",b"key",b"flag",b"ctf"][i%5]
        plain=b"noise::"+flag+b"::end"
        enc=bytes(b ^ key[j%len(key)] for j,b in enumerate(plain))
        add(f"xor_{i:02d}","xor",enc,flag.decode(),"bytes")
    # 20 compressed
    compressors=[("gz",_gzip.compress),("zlib",_zlib.compress),("bz2",_bz2.compress),("xz",_lzma.compress)]
    for i in range(20):
        flag=f"ctf_cs{{ff_comp_{i:02d}_ok}}".encode()
        nm,fn=compressors[i%len(compressors)]
        add(f"compressed_{i:02d}_{nm}","compressed",fn(b"data "+flag+b"\n"),flag.decode(),"bytes")
    # 15 JWT/JSON
    for i in range(15):
        flag=f"ctf_cs{{ff_jwt_{i:02d}_ok}}"
        h=_b64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        p=_b64.urlsafe_b64encode(json.dumps({"msg":flag}).encode()).decode().rstrip("=")
        add(f"jwt_{i:02d}","jwt","token="+h+"."+p+".",flag)
    # 15 classical
    for i in range(15):
        flag=f"ctf_cs{{ff_classic_{i:02d}_ok}}"
        if i%3==0:
            blob=" ".join({v:k for k,v in MORSE.items()}.get(c,"") for c in flag.lower() if c.isalnum())
        elif i%3==1:
            src="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"; dst="zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"
            blob=flag.translate(str.maketrans(src,dst))
        else:
            blob=dp_rot_text(flag,13)
        add(f"classic_{i:02d}","classic",blob,flag)
    # 15 non-format answers
    for i in range(15):
        ans=f"answerword{i:02d}"
        add(f"answer_{i:02d}","answer",f"Užduotis\natsakymas: {ans}\n",ans)
    return cases[:140]
def mb_run_100_benchmark():
    cases=mb_gen_cases()
    results=[]
    for c in cases:
        expected=c["expected"]; blob=c["blob"]
        text=blob.decode("latin1","ignore") if isinstance(blob,(bytes,bytearray)) else str(blob)
        data=bytes(blob) if isinstance(blob,(bytes,bytearray)) else text.encode()
        chain=mb_fast_chain(text,max_depth=7,state_limit=1200)
        chain += ff_extra_decoders(text)
        chain += mb_caesar_and_vigenere_candidates(text)
        found_flags=vf_primary_flags(text,limit=10,scan_limit=50000)+[f for item in chain for f in item.get("flags",[])]
        for item in mb_xor_short_keys(data): found_flags += item.get("flags",[])
        fake_report={"flags":list(dict.fromkeys(found_flags)),"verified_flags":[],"strings":[text],"outputs":[{"ok":True,"out":text}],"chain_results":chain,"previews":[],"artifacts":[]}
        for item in try_decompress_bytes(data)[:10]:
            out=item.get("output","")
            fs=vf_primary_flags(out,limit=10,scan_limit=50000)
            found_flags += fs
            fake_report["chain_results"].append({"type":item.get("type"),"output":out,"score":item.get("score",0),"flags":fs})
        fake_report["flags"]=list(dict.fromkeys(found_flags))
        answers=[a["value"] for a in vf_collect_answer_candidates(fake_report)]
        ok=(expected in found_flags) or (expected in answers) or (expected in json.dumps(chain))
        results.append({"name":c["name"],"kind":c["kind"],"expected":expected,"ok":ok,"flags":list(dict.fromkeys(found_flags))[:10],"answers":answers[:10]})
    passed=sum(1 for r in results if r["ok"])
    by_kind={}
    for r in results:
        by_kind.setdefault(r["kind"],{"ok":0,"total":0})
        by_kind[r["kind"]]["total"]+=1
        if r["ok"]: by_kind[r["kind"]]["ok"]+=1
    return {"ok":passed==len(results),"passed":passed,"total":len(results),"by_kind":by_kind,"results":results}
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
    # Avoid accidental short fragments like ctf_cs{abcde}; real contest flags are almost always longer.
    if len(inner)<6 or len(inner)>120:
        return False
    if any(ord(c)<32 or ord(c)>126 for c in inner):
        return False
    if "ctf_cs" in low:
        return False
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_\-:.+]{5,120}", inner):
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
def mb_gen_cases():
    import base64 as _b64, urllib.parse as _url, gzip as _gzip, zlib as _zlib, bz2 as _bz2, lzma as _lzma
    cases=[]
    def add(name, kind, blob, expected, mode="text"):
        cases.append({"name":name,"kind":kind,"blob":blob,"expected":expected,"mode":mode})
    # 50 encoding stacks
    for i in range(50):
        flag=f"ctf_cs{{ff_enc_{i:02d}_ok}}".encode()
        if i%10==0: blob=_b64.b64encode(flag).decode()
        elif i%10==1: blob=_b64.b64encode(_b64.b64encode(flag)).decode()
        elif i%10==2: blob=_b64.b64encode(flag).decode().encode().hex()
        elif i%10==3: blob=_b64.b64encode(_b64.b64encode(flag).decode().encode().hex().encode()).decode()
        elif i%10==4: blob=_url.quote(_b64.b64encode(flag).decode())
        elif i%10==5: blob=" ".join(str(b) for b in flag)
        elif i%10==6: blob="".join(f"{b:08b}" for b in flag)
        elif i%10==7: blob=_b64.b32encode(flag).decode()
        elif i%10==8:
            n=int.from_bytes(flag,"big"); out=""
            while n: n,rem=divmod(n,58); out=B58_ALPHABET[rem]+out
            blob=out
        else: blob=html.escape(_b64.b64encode(flag).decode())
        add(f"encoding_{i:02d}","encoding","blob="+blob,flag.decode())
    # 25 XOR
    for i in range(25):
        flag=f"ctf_cs{{ff_xor_{i:02d}_ok}}".encode()
        key=[b"k",b"xy",b"key",b"flag",b"ctf"][i%5]
        plain=b"noise::"+flag+b"::end"
        enc=bytes(b ^ key[j%len(key)] for j,b in enumerate(plain))
        add(f"xor_{i:02d}","xor",enc,flag.decode(),"bytes")
    # 20 compressed
    compressors=[("gz",_gzip.compress),("zlib",_zlib.compress),("bz2",_bz2.compress),("xz",_lzma.compress)]
    for i in range(20):
        flag=f"ctf_cs{{ff_comp_{i:02d}_ok}}".encode()
        nm,fn=compressors[i%len(compressors)]
        add(f"compressed_{i:02d}_{nm}","compressed",fn(b"data "+flag+b"\n"),flag.decode(),"bytes")
    # 15 JWT/JSON
    for i in range(15):
        flag=f"ctf_cs{{ff_jwt_{i:02d}_ok}}"
        h=_b64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        p=_b64.urlsafe_b64encode(json.dumps({"msg":flag}).encode()).decode().rstrip("=")
        add(f"jwt_{i:02d}","jwt","token="+h+"."+p+".",flag)
    # 15 classical. Morse produces non-format answer because braces/underscores are not Morse-safe.
    for i in range(15):
        if i%3==0:
            plain=f"ctfcsffclassic{i:02d}ok"
            rev={v:k for k,v in MORSE.items()}
            blob=" ".join(rev.get(c,"") for c in plain.lower() if c.isalnum())
            add(f"classic_morse_{i:02d}","classic",blob,plain)
        elif i%3==1:
            flag=f"ctf_cs{{ff_classic_{i:02d}_ok}}"
            src="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"; dst="zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"
            blob=flag.translate(str.maketrans(src,dst))
            add(f"classic_atbash_{i:02d}","classic",blob,flag)
        else:
            flag=f"ctf_cs{{ff_classic_{i:02d}_ok}}"
            blob=dp_rot_text(flag,13)
            add(f"classic_rot13_{i:02d}","classic",blob,flag)
    # 15 non-format answers
    for i in range(15):
        ans=f"answerword{i:02d}"
        add(f"answer_{i:02d}","answer",f"Užduotis\natsakymas: {ans}\n",ans)
    return cases[:140]
def cs_artifact_log_reconstruct(path, root, report):
    arts=[]
    try:
        lines=Path(path).read_text(encoding="utf-8",errors="ignore").splitlines()
        entries=[]
        for line in lines:
            try:
                obj=json.loads(line)
                if "x" in obj and "y" in obj and isinstance(obj.get("rows"),list):
                    entries.append(obj)
            except Exception:
                pass
        if not entries:
            return []
        allowed=set(" $/\\_|")
        valid=[]
        for e in entries:
            rows=e.get("rows",[])
            if rows and all(all(ch in allowed for ch in str(r)) for r in rows):
                valid.append(e)
        use=valid if len(valid)>=5 else entries
        maxx=max(int(e["x"])+max(len(str(r)) for r in e["rows"]) for e in use)
        maxy=max(int(e["y"])+len(e["rows"]) for e in use)
        canvas=[[" "]*maxx for _ in range(maxy)]
        for e in use:
            for dy,row in enumerate(e["rows"]):
                for dx,ch in enumerate(str(row)):
                    if ch!=" ":
                        canvas[int(e["y"])+dy][int(e["x"])+dx]=ch
        art="\n".join("".join(r).rstrip() for r in canvas)
        outdir=root/"generated"/"cybersprintcore"/safe(report.get("name","artifact"))
        outdir.mkdir(parents=True,exist_ok=True)
        p=outdir/"artifact_log_reconstructed_ascii.txt"
        p.write_text(art,encoding="utf-8",errors="ignore")
        arts.append({"kind":"artifact_log_reconstruction","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CyberSprintCore","score":135,"note":"Reconstructed JSON x/y ASCII-art tiles; open this visually.","exists":True,"size":p.stat().st_size,"file":report.get("rel","")})
        # Also save cleaned valid rows count/report.
        meta=outdir/"artifact_log_reconstruction_meta.json"
        meta.write_text(json.dumps({"entries":len(entries),"valid_ascii_tiles":len(valid),"width":maxx,"height":maxy},indent=2),encoding="utf-8")
        arts.append({"kind":"artifact_log_meta","name":meta.name,"path":str(meta),"url":"/api/raw?path="+str(meta),"source":"CyberSprintCore","score":85,"note":"Artifact reconstruction statistics","exists":True,"size":meta.stat().st_size,"file":report.get("rel","")})
    except Exception as e:
        pass
    return arts
def cs_morse_hex_url_chain(text):
    outs=[]
    text=str(text or "")[:20000]
    try:
        mor=ff_morse_decode(text)
        if mor:
            outs.append(("morse",mor))
            if re.fullmatch(r"[0-9a-fA-F]{8,}",mor) and len(mor)%2==0:
                hx=bytes.fromhex(mor).decode("utf-8","replace")
                outs.append(("morse->hex",hx))
                try:
                    u=urllib.parse.unquote(hx)
                    if u!=hx: outs.append(("morse->hex->url",u))
                except Exception:
                    pass
    except Exception:
        pass
    return outs
def cs_text_special_artifacts(root, report, data):
    arts=[]
    path=Path(report.get("path",""))
    text=data.decode("utf-8","ignore")
    outdir=root/"generated"/"cybersprintcore"/safe(report.get("name","text"))
    outdir.mkdir(parents=True,exist_ok=True)
    # Morse->hex/url chain artifact, useful for Skaitmeninė archeologija layer.txt
    chain=cs_morse_hex_url_chain(text)
    if chain:
        p=outdir/"morse_hex_url_chain.txt"
        p.write_text("\n\n".join(f"## {name}\n{val}" for name,val in chain),encoding="utf-8",errors="ignore")
        arts.append({"kind":"morse_hex_url_chain","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CyberSprintCore","score":145,"note":"Morse decoded; if hex, hex decoded too.","exists":True,"size":p.stat().st_size,"file":report.get("rel","")})
    # Log time anomaly extraction
    if path.suffix.lower() in [".log",".txt"] and ("Time anomaly" in text or "Time drift" in text):
        import datetime as _dt
        events=[]
        for line in text.splitlines():
            if "Time anomaly" in line or "Time drift" in line:
                m=re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z\s+(\S+)\s+(\S+)\s+(.*)",line)
                if m:
                    try:
                        dt=_dt.datetime.fromisoformat(m.group(1))
                        events.append({"line":line,"t":dt,"module":m.group(2),"level":m.group(3),"msg":m.group(4)})
                    except Exception:
                        pass
        if events:
            base_t=events[0]["t"]
            secs=[int((e["t"]-base_t).total_seconds()) for e in events]
            deltas=[secs[i]-secs[i-1] for i in range(1,len(secs))]
            sec_of_min=[e["t"].second for e in events]
            def asc(vals):
                return "".join(chr(v) if 32<=v<127 else "." for v in vals)
            obj={
                "count":len(events),
                "seconds_from_first":secs,
                "deltas":deltas,
                "second_of_minute":sec_of_min,
                "seconds_ascii":asc(secs),
                "deltas_ascii":asc(deltas),
                "second_of_minute_ascii":asc(sec_of_min),
                "modules":"".join(e["module"][0] for e in events),
                "levels":"".join(e["level"][0] for e in events),
                "events":[{k:v for k,v in e.items() if k!="t"} for e in events[:400]]
            }
            p=outdir/"time_anomaly_analysis.json"
            p.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding="utf-8")
            arts.append({"kind":"time_anomaly_analysis","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CyberSprintCore","score":130,"note":"Extracted time anomaly/drift sequences, deltas and ASCII views.","exists":True,"size":p.stat().st_size,"file":report.get("rel","")})
    # Artifact reconstruction
    if path.name.lower()=="artifact.log":
        arts += cs_artifact_log_reconstruct(path, root, report)
    return arts
def cs_pcap_scalar_artifacts(root, report, data):
    if report.get("kind")!="pcap" and Path(report.get("path","")).suffix.lower() not in [".pcap",".pcapng"]:
        return []
    outdir=root/"generated"/"cybersprintcore"/safe(report.get("name","pcap"))
    outdir.mkdir(parents=True,exist_ok=True)
    arts=[]
    # Strings and protocol-ish clues
    ss=py_strings(data,limit=20000)
    interesting=[]
    for s in ss:
        low=s.lower()
        if any(k in low for k in ["ctf","flag","http","host:","get ","post ","cookie","token","secret","password","dns","user-agent","authorization"]) or re.search(r"[a-z0-9.-]+\.[a-z]{2,}",low):
            interesting.append(s)
    p=outdir/"pcap_strings_interesting.txt"
    p.write_text("\n".join(interesting[:5000]),encoding="utf-8",errors="ignore")
    arts.append({"kind":"pcap_interesting_strings","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CyberSprintCore","score":110 if interesting else 50,"note":"Interesting strings from PCAP/PCAPNG without tshark.","exists":True,"size":p.stat().st_size,"file":report.get("rel","")})
    # Raw IPv4 scanner: extracts candidate packet fields from any offset.
    rows=[]
    b=data
    for off in range(0,max(0,len(b)-20)):
        v=b[off]>>4
        ihl=(b[off]&15)*4
        if v==4 and 20<=ihl<=60 and off+ihl<=len(b):
            total=int.from_bytes(b[off+2:off+4],"big")
            proto=b[off+9]
            if 20<=total<=65535 and off+total<=len(b):
                src=".".join(map(str,b[off+12:off+16]))
                dst=".".join(map(str,b[off+16:off+20]))
                ident=int.from_bytes(b[off+4:off+6],"big")
                ttl=b[off+8]
                rows.append({"off":off,"len":total,"id":ident,"ttl":ttl,"proto":proto,"src":src,"dst":dst})
                if len(rows)>=5000: break
    if rows:
        ids=[r["id"] for r in rows]
        ttls=[r["ttl"] for r in rows]
        lens=[r["len"] for r in rows]
        def ascii_low(vals):
            return "".join(chr(v&255) if 32<= (v&255) <127 else "." for v in vals)
        obj={"packet_count":len(rows),"first_rows":rows[:300],"id_low_ascii":ascii_low(ids),"ttl_ascii":ascii_low(ttls),"len_low_ascii":ascii_low(lens)}
        p2=outdir/"pcap_ipv4_scalar_fields.json"
        p2.write_text(json.dumps(obj,indent=2),encoding="utf-8")
        arts.append({"kind":"pcap_ipv4_scalar_fields","name":p2.name,"path":str(p2),"url":"/api/raw?path="+str(p2),"source":"CyberSprintCore","score":135,"note":"IPv4 id/ttl/len scalar extraction for covert channels.","exists":True,"size":p2.stat().st_size,"file":report.get("rel","")})
    return arts
def cs_pyc_decode_artifacts(root, report, data):
    if Path(report.get("path","")).suffix.lower()!=".pyc":
        return []
    arts=[]
    outdir=root/"generated"/"cybersprintcore"/safe(report.get("name","pyc")); outdir.mkdir(parents=True,exist_ok=True)
    try:
        import marshal
        code=None
        for off in [16,12,8]:
            try:
                code=marshal.loads(data[off:])
                break
            except Exception:
                pass
        consts=[]
        def walk(c):
            for x in getattr(c,"co_consts",[]):
                if isinstance(x,(str,bytes,int,float)):
                    consts.append(x)
                elif hasattr(x,"co_consts"):
                    walk(x)
        if code:
            walk(code)
        decoded=[]
        for c in consts:
            s=c.decode("utf-8","ignore") if isinstance(c,bytes) else str(c)
            decoded.append(s)
            for name,out in mb_basic_decode_steps(s):
                decoded.append(f"[{name}] {out}")
            for name,out in cs_morse_hex_url_chain(s):
                decoded.append(f"[{name}] {out}")
        p=outdir/"pyc_constants_decoded.txt"
        p.write_text("\n".join(decoded[:5000]),encoding="utf-8",errors="ignore")
        arts.append({"kind":"pyc_constants_decoded","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CyberSprintCore","score":150,"note":"PYC constants with base/url/hex decode attempts; no code execution.","exists":True,"size":p.stat().st_size,"file":report.get("rel","")})
    except Exception:
        pass
    return arts
def cs_archive_extract_artifacts(root, report, data):
    arts=[]
    path=Path(report.get("path",""))
    outdir=root/"generated"/"cybersprintcore_archive"/safe(report.get("name","archive"))
    try:
        if path.suffix.lower() in [".tgz",".gz"] and tarfile.is_tarfile(path):
            outdir.mkdir(parents=True,exist_ok=True)
            with tarfile.open(path) as tar:
                safe_members=[]
                for m in tar.getmembers()[:200]:
                    if m.isfile():
                        name=safe(Path(m.name).name)
                        f=tar.extractfile(m)
                        if f:
                            dest=outdir/name
                            dest.write_bytes(f.read())
                            safe_members.append(str(dest))
            p=outdir/"tar_members.json"
            p.write_text(json.dumps(safe_members,indent=2),encoding="utf-8")
            arts.append({"kind":"tar_tgz_extracted_members","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CyberSprintCore","score":125,"note":"Extracted tar/tgz child files safely.","exists":True,"size":p.stat().st_size,"file":report.get("rel","")})
        elif path.suffix.lower()==".zip":
            outdir.mkdir(parents=True,exist_ok=True)
            files=[]
            with zipfile.ZipFile(path) as z:
                for info in z.infolist()[:200]:
                    if info.is_dir(): continue
                    dest=outdir/safe(Path(info.filename).name)
                    dest.write_bytes(z.read(info))
                    files.append(str(dest))
            p=outdir/"zip_members.json"
            p.write_text(json.dumps(files,indent=2),encoding="utf-8")
            arts.append({"kind":"zip_extracted_members","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CyberSprintCore","score":125,"note":"Extracted zip child files safely.","exists":True,"size":p.stat().st_size,"file":report.get("rel","")})
    except Exception:
        pass
    return arts
def cs_enhance_report(root, report, data):
    arts=[]
    path=Path(report.get("path",""))
    if report.get("kind") in ["text","generic"] or path.suffix.lower() in [".txt",".log",".json"]:
        arts += cs_text_special_artifacts(root, report, data)
    arts += cs_pcap_scalar_artifacts(root, report, data)
    arts += cs_pyc_decode_artifacts(root, report, data)
    arts += cs_archive_extract_artifacts(root, report, data)
    if arts:
        existing=set(a.get("path") for a in report.get("artifacts",[]))
        for a in arts:
            if a.get("path") not in existing:
                report.setdefault("artifacts",[]).append(a)
                report.setdefault("transformations",[]).append(a)
                existing.add(a.get("path"))
    return report
def rb_enhance_report(root, report, data):
    # Keep old RealBench enhancements and add CyberSprintCore special handlers.
    arts=[]
    try: arts += rb_decompress_file_artifacts(root, report, data)
    except Exception: pass
    try: arts += rb_pcap_fallback_artifacts(root, report, data)
    except Exception: pass
    try: arts += rb_pyc_static_artifact(root, report, data)
    except Exception: pass
    try: arts += rb_text_log_patterns(root, report, data)
    except Exception: pass
    if arts:
        existing=set(a.get("path") for a in report.get("artifacts",[]))
        for a in arts:
            if a.get("path") not in existing:
                report.setdefault("artifacts",[]).append(a)
                report.setdefault("transformations",[]).append(a)
                existing.add(a.get("path"))
    try:
        cs_enhance_report(root, report, data)
    except Exception:
        pass
    return report
def cs_static_benchmark_zip(zip_path="/mnt/data/Cyber Sprint 2026 1 etapas.zip"):
    """Fast benchmark over the user's real zip: no full binary execution, no web; creates no projects."""
    zip_path=Path(zip_path)
    manifest=rb_zip_manifest(zip_path)
    results=[]
    if not zip_path.exists():
        return {"ok":False,"error":"zip not found","path":str(zip_path)}
    tmp=BASE/"generated"/"cybersprint_zip_bench"
    if tmp.exists():
        shutil.rmtree(tmp,ignore_errors=True)
    tmp.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(zip_path) as z:
        for ch in manifest.get("challenges",[]):
            files=ch.get("files",[])
            title=ch.get("category","")+"/"+ch.get("challenge","")
            report={"title":title,"category":ch.get("category"),"challenge":ch.get("challenge"),"files":len(files),"flags":[],"answers":[],"artifacts":[],"notes":[]}
            for f in files:
                name=f["name"]
                data=z.read(name)
                rel=Path(name).name
                fake_root=tmp/safe(ch.get("category","cat")+"_"+ch.get("challenge","ch"))
                fake_root.mkdir(parents=True,exist_ok=True)
                fp=fake_root/safe(rel)
                fp.write_bytes(data)
                kind="text" if Path(rel).suffix.lower() in [".txt",".log",".json"] else ("pcap" if Path(rel).suffix.lower() in [".pcap",".pcapng"] else "generic")
                r={"name":rel,"rel":rel,"path":str(fp),"kind":kind,"artifacts":[],"transformations":[],"strings":py_strings(data,limit=1000),"outputs":[],"flags":vf_primary_flags(data.decode('utf-8','ignore'),limit=20),"chain_results":[],"previews":[],"verified_flags":[]}
                rb_enhance_report(fake_root,r,data)
                text=data.decode("utf-8","ignore")
                # direct chain and specials
                for c in mb_fast_chain(text,max_depth=6,state_limit=700)[:30]+ff_extra_decoders(text)[:20]:
                    r["chain_results"].append(c)
                    for fl in c.get("flags",[]):
                        if fl not in r["flags"]: r["flags"].append(fl)
                r["answer_candidates"]=vf_collect_answer_candidates(r)
                report["flags"]+=r.get("flags",[])
                report["answers"]+=[a.get("value") for a in r.get("answer_candidates",[])[:8]]
                report["artifacts"]+=[{"name":a.get("name"),"kind":a.get("kind"),"path":a.get("path"),"score":a.get("score")} for a in r.get("artifacts",[])[:10]]
                if r.get("chain_results"):
                    report["notes"].append("chain:"+str(r["chain_results"][0].get("type")))
            report["flags"]=list(dict.fromkeys([x for x in report["flags"] if smartsolve_strict_target_flag_ok(x)]))
            report["answers"]=list(dict.fromkeys([x for x in report["answers"] if x]))[:20]
            report["status"]="flag" if report["flags"] else ("answer/artifact" if report["answers"] or report["artifacts"] else "unresolved")
            results.append(report)
    solved=sum(1 for r in results if r["flags"])
    has_signal=sum(1 for r in results if r["status"]!="unresolved")
    return {"ok":True,"zip":str(zip_path),"total":len(results),"with_flags":solved,"with_signal":has_signal,"unresolved":len(results)-has_signal,"results":results}
def cybersprint_benchmark_get(path:str="/mnt/data/Cyber Sprint 2026 1 etapas.zip"):
    try:
        return cs_static_benchmark_zip(path)
    except Exception as e:
        return {"ok":False,"error":str(e)}
async def cybersprint_benchmark_post(path:str=Form("/mnt/data/Cyber Sprint 2026 1 etapas.zip")):
    try:
        return cs_static_benchmark_zip(path)
    except Exception as e:
        return {"ok":False,"error":str(e)}
LT_TEMPLATE_WORDS = [
    "pavadinimas","gatves","gatvės","pastato","numeris","vietos","rastos",
    "frazė","fraze","tekstas","sha256_kodas","sha256","kodas","rastastekstas",
    "rastas_tekstas","rasta_fraze","rasta_frazė"
]
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
    # Lithuanian template placeholders from task statements must not be promoted.
    if any(w in norm for w in LT_TEMPLATE_WORDS):
        return False
    if len(inner)<6 or len(inner)>120:
        return False
    if any(ord(c)<32 or ord(c)>126 for c in inner):
        return False
    if "ctf_cs" in low:
        return False
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_\-:.+]{5,120}", inner):
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
def vf_answer_score(text, source=""):
    s=str(text or "").strip()
    if not s or len(s)<3 or len(s)>180:
        return 0
    low=s.lower()
    score=0
    if PRIMARY_FLAG_RE.search(s) and smartsolve_strict_target_flag_ok(PRIMARY_FLAG_RE.search(s).group(0)): score+=300
    if re.fullmatch(r"[a-fA-F0-9]{64}",s): score+=160
    if re.fullmatch(r"[a-fA-F0-9]{32,40}",s): score+=110
    if re.fullmatch(r"-?\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+",s): score+=130
    if re.fullmatch(r"[A-Za-z0-9_\-:.+/@]{5,140}",s): score+=45
    if any(k in low for k in ["answer","atsakymas","ats:","raktas","key","secret","slapta","slaptažodis","pass:","password","code","kodas","token"]): score+=70
    # Penalize full challenge prose, template formats, and instruction sentences.
    if len(s)>100 and not re.search(r"[A-Za-z0-9_\-:.+/@]{20,}",s): score-=80
    if any(w in low for w in ["vėliavėlės formatas","veliaveles formatas","formatas ctf_cs","užduotis","jūsų užduotis","jusu uzduotis","kur ... yra"]): score-=140
    if any(w in low for w in ["sample","dummy","fake","placeholder","example","ctf_cs{...}"]): score-=130
    if "�" in s: score-=80
    if source and any(x in source.lower() for x in ["ocr","qr","artifact","chain"]): score+=20
    return score
def vf_add_answer(cands, value, source, why="", score_bonus=0):
    value=str(value or "").strip()
    if not value:
        return
    # Strip common prose wrappers if line is key: value.
    m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|slaptazodis|password|pass|code|kodas|token)\s*[:=]\s*(.+)$",value,re.I)
    if m and len(m.group(1).strip())<160:
        value=m.group(1).strip()
    sc=vf_answer_score(value, source)+int(score_bonus)
    if sc>=70:
        cands.append({"value":value[:220],"source":str(source)[:180],"why":str(why)[:320],"score":sc})
def cs_static_benchmark_zip(zip_path="/mnt/data/Cyber Sprint 2026 1 etapas.zip"):
    zip_path=Path(zip_path)
    manifest=rb_zip_manifest(zip_path)
    results=[]
    if not zip_path.exists():
        return {"ok":False,"error":"zip not found","path":str(zip_path)}
    tmp=BASE/"generated"/"cybersprint_zip_bench"
    if tmp.exists():
        shutil.rmtree(tmp,ignore_errors=True)
    tmp.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(zip_path) as z:
        for ch in manifest.get("challenges",[]):
            files=ch.get("files",[])
            title=ch.get("category","")+"/"+ch.get("challenge","")
            report={"title":title,"category":ch.get("category"),"challenge":ch.get("challenge"),"files":len(files),"flags":[],"answers":[],"artifacts":[],"notes":[]}
            for f in files:
                name=f["name"]
                data=z.read(name)
                rel=Path(name).name
                fake_root=tmp/safe(ch.get("category","cat")+"_"+ch.get("challenge","ch"))
                fake_root.mkdir(parents=True,exist_ok=True)
                fp=fake_root/safe(rel); fp.write_bytes(data)
                kind="text" if Path(rel).suffix.lower() in [".txt",".log",".json"] else ("pcap" if Path(rel).suffix.lower() in [".pcap",".pcapng"] else "generic")
                r={"name":rel,"rel":rel,"path":str(fp),"kind":kind,"artifacts":[],"transformations":[],"strings":py_strings(data,limit=1000),"outputs":[],"flags":vf_primary_flags(data.decode('utf-8','ignore'),limit=20),"chain_results":[],"previews":[],"verified_flags":[]}
                rb_enhance_report(fake_root,r,data)
                text=data.decode("utf-8","ignore")
                for c in mb_fast_chain(text,max_depth=6,state_limit=700)[:30]+ff_extra_decoders(text)[:20]:
                    r["chain_results"].append(c)
                    for fl in c.get("flags",[]):
                        if fl not in r["flags"] and smartsolve_strict_target_flag_ok(fl): r["flags"].append(fl)
                r["answer_candidates"]=vf_collect_answer_candidates(r)
                report["flags"]+=[x for x in r.get("flags",[]) if smartsolve_strict_target_flag_ok(x)]
                # Keep only shorter/high-value answers.
                for a in r.get("answer_candidates",[])[:8]:
                    val=a.get("value","")
                    if val and len(val)<=180 and vf_answer_score(val,a.get("source",""))>=70:
                        report["answers"].append(val)
                report["artifacts"]+=[{"name":a.get("name"),"kind":a.get("kind"),"path":a.get("path"),"score":a.get("score")} for a in r.get("artifacts",[])[:10]]
                if r.get("chain_results"): report["notes"].append("chain:"+str(r["chain_results"][0].get("type")))
            report["flags"]=list(dict.fromkeys(report["flags"]))
            report["answers"]=list(dict.fromkeys(report["answers"]))[:20]
            report["status"]="flag" if report["flags"] else ("answer/artifact" if report["answers"] or report["artifacts"] else "unresolved")
            results.append(report)
    solved=sum(1 for r in results if r["flags"])
    has_signal=sum(1 for r in results if r["status"]!="unresolved")
    return {"ok":True,"zip":str(zip_path),"total":len(results),"with_flags":solved,"with_signal":has_signal,"unresolved":len(results)-has_signal,"results":results}
AGENTFORGE_MAX_CHILD_BYTES = 1_500_000
AGENTFORGE_MAX_CHILDREN = 80
def af_trace(report, step, detail="", score=0, artifact=None):
    report.setdefault("agent_trace", []).append({
        "step": str(step)[:120],
        "detail": str(detail)[:600],
        "score": int(score or 0),
        "artifact": artifact or "",
        "time": now() if "now" in globals() else ""
    })
def af_art(root, report, name, content, kind="agentforge_artifact", score=80, note=""):
    outdir = root / "generated" / "agentforge" / safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p = outdir / safe(name)
    try:
        if isinstance(content, (bytes, bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content), encoding="utf-8", errors="ignore")
        art = {
            "kind": kind,
            "name": p.name,
            "path": str(p),
            "url": "/api/raw?path=" + str(p),
            "source": "AgentForge",
            "score": int(score),
            "note": note or kind,
            "exists": True,
            "size": p.stat().st_size,
            "file": report.get("rel","")
        }
        report.setdefault("artifacts", []).append(art)
        report.setdefault("transformations", []).append(art)
        af_trace(report, "artifact created", f"{kind}: {p.name}", score, str(p))
        return art
    except Exception as e:
        af_trace(report, "artifact create failed", f"{name}: {e}", 0)
        return None
def af_read_textish(path, max_bytes=AGENTFORGE_MAX_CHILD_BYTES):
    p = Path(path)
    data = p.read_bytes()[:max_bytes]
    txt = data.decode("utf-8", "ignore")
    if not txt and data:
        txt = data.decode("latin1", "ignore")
    return data, txt
def af_add_chain(report, chain_items, source_bonus=0):
    old = set((c.get("type"), (c.get("output","") or "")[:240]) for c in report.get("chain_results", []))
    added = 0
    for c in sorted(chain_items, key=lambda x: x.get("score",0), reverse=True):
        k = (c.get("type"), (c.get("output","") or "")[:240])
        if k in old:
            continue
        old.add(k)
        c = dict(c)
        c["score"] = int(c.get("score",0)) + int(source_bonus)
        report.setdefault("chain_results", []).insert(0, c)
        for f in c.get("flags", []) or []:
            if smartsolve_strict_target_flag_ok(f) and f not in report.setdefault("flags", []):
                report["flags"].append(f)
                af_trace(report, "flag from chain", f"{f} via {c.get('type')}", c.get("score",0))
        added += 1
    if added:
        report["chain_results"] = sorted(report.get("chain_results", []), key=lambda x:x.get("score",0), reverse=True)[:320]
    return added
def af_run_text_decoders(report, root, text, label="text", budget=1600):
    items = []
    text = str(text or "")[:60000]
    try:
        items += mb_fast_chain(text, max_depth=8, state_limit=budget)
    except Exception as e:
        af_trace(report, "mb_fast_chain failed", str(e))
    try:
        items += ff_extra_decoders(text)
    except Exception as e:
        af_trace(report, "extra decoders failed", str(e))
    try:
        items += mb_caesar_and_vigenere_candidates(text)
    except Exception:
        pass
    try:
        for name, out in cs_morse_hex_url_chain(text):
            flags = vf_primary_flags(out, limit=10, scan_limit=30000)
            items.append({"type":"agentforge_"+name, "input":label, "output":out, "flags":flags, "score":180 if flags else 100, "chain_source":label+" -> "+name})
    except Exception:
        pass
    n = af_add_chain(report, items, 0)
    af_trace(report, "text decoders", f"{label}: added {n} chain items", 80 if n else 20)
    return n
def af_decompress_recursive(report, root, data, label="data", depth=0, max_depth=3):
    if depth > max_depth or not data:
        return []
    arts = []
    # try_decompress_bytes returns text outputs, but also create child files.
    for item in try_decompress_bytes(data)[:12]:
        out = item.get("output", "")
        if not out:
            continue
        art = af_art(root, report, f"decompressed_d{depth}_{safe(label)}_{safe(item.get('type','out'))}.txt", out, "agentforge_decompressed", item.get("score",80)+40, "Recursive decompression output")
        if art:
            arts.append(art)
            af_run_text_decoders(report, root, out, "decompressed:"+label, 700)
            # Recurse on text bytes in case nested base/gzip represented as bytes.
            try:
                arts += af_decompress_recursive(report, root, out.encode(), label+"_"+item.get("type","out"), depth+1, max_depth)
            except Exception:
                pass
    # Direct gzip/bz2/xz/zlib bytes as binary artifacts.
    funcs = []
    try: funcs.append(("gzip", gzip.decompress))
    except Exception: pass
    funcs += [("bz2", bz2.decompress), ("lzma", lzma.decompress), ("zlib", zlib.decompress)]
    seen = set()
    for nm, fn in funcs:
        try:
            raw = fn(data)
            if not raw or len(raw) > 8_000_000:
                continue
            h = hashlib.sha256(raw[:2_000_000]).hexdigest()[:12]
            if h in seen:
                continue
            seen.add(h)
            ext = ".txt" if dp_is_mostly_printable(raw.decode("utf-8","ignore")[:3000]) else ".bin"
            art = af_art(root, report, f"raw_decompressed_d{depth}_{safe(label)}_{nm}_{h}{ext}", raw, "agentforge_raw_decompressed", 130, "Raw decompressed bytes")
            if art:
                arts.append(art)
                txt = raw.decode("utf-8","ignore")
                if txt:
                    af_run_text_decoders(report, root, txt, "raw_decompressed:"+label, 800)
                if depth < max_depth:
                    arts += af_decompress_recursive(report, root, raw, label+"_"+nm, depth+1, max_depth)
        except Exception:
            pass
    return arts
