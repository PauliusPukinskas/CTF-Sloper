# Auto-split from sloper_legacy_monolith.py lines 4389-...
def project_summary(reports, meta):
    # Build on existing summary logic but include Answer Candidates.
    flags=[]; verified_map={}; kinds={}; evidence=[]; chains=[]; actions=[]; missing=[]; agents=[]; transforms=[]; verifyloops=[]; artifacts=[]; recipes=[]; graphs=[]; answers=[]
    for r in reports:
        try: vf_postprocess(r, Path(r.get("path","")).parents[1] if r.get("path") else BASE)
        except Exception:
            try: smartsolve_postprocess(r, BASE)
            except Exception: pass
        kinds[r.get("kind","?")]=kinds.get(r.get("kind","?"),0)+1
        for v in r.get("verified_flags_visible", []):
            key=(v.get("flag") or "").lower()
            vv={"file":r.get("rel"),**v}
            if key and (key not in verified_map or vv.get("score",0)>verified_map[key].get("score",0)):
                verified_map[key]=vv
        for f in r.get("flags", []):
            if smartsolve_strict_target_flag_ok(f):
                flags.append({"file":r.get("rel"),"flag":f,"score":999,"status":"promoted"})
        for ans in r.get("answer_candidates",[])[:60]:
            answers.append({"file":r.get("rel"),**ans})
        for f in r.get("findings",[])[:60]:
            if not is_noisy_candidate_text(f.get("value",""), f.get("why",""), f.get("type","")):
                evidence.append({"file":r.get("rel"),**f})
        for c in r.get("chain_results",[])[:30]:
            out=(c.get("output","") or "")[:900]
            if c.get("score",0)>70 and not is_noisy_candidate_text(out,c.get("type",""),"chain"):
                chains.append({"file":r.get("rel"),"type":c.get("type"),"source":c.get("chain_source"),"score":c.get("score"),"output":out})
        for s in r.get("next_steps",[])[:10]: actions.append({"file":r.get("rel"),**s})
        for a in r.get("agent_runs",[])[:12]: agents.append({"file":r.get("rel"),"kind":r.get("kind"),**a})
        for t in r.get("transformations",[])[:50]: transforms.append({"file":r.get("rel"),**t})
        if r.get("verifyloop"): verifyloops.append({"file":r.get("rel"),"kind":r.get("kind"),**r.get("verifyloop",{})})
        for art in r.get("artifacts",[])[:260]: artifacts.append(art)
        for rec in r.get("recipe_runs",[])[:12]: recipes.append({"file":r.get("rel"),"kind":r.get("kind"),**rec})
        if r.get("artifact_graph"): graphs.append({"file":r.get("rel"),"graph":r.get("artifact_graph")})
        for o in r.get("outputs",[]):
            if not o.get("ok") and "not installed" in (o.get("out","").lower()):
                missing.append((o.get("out","").split() or ["unknown"])[0])
    flag_map={}
    for f in flags:
        key=(f.get("flag") or "").lower()
        if key and (key not in flag_map or f.get("score",0)>flag_map[key].get("score",0)): flag_map[key]=f
    ans_map={}
    for a in answers:
        key=(a.get("value") or "").lower()
        if key and (key not in ans_map or a.get("score",0)>ans_map[key].get("score",0)): ans_map[key]=a
    flags=sorted(flag_map.values(),key=lambda x:x.get("score",0),reverse=True)[:60]
    answers=sorted(ans_map.values(),key=lambda x:x.get("score",0),reverse=True)[:180]
    verified_all=sorted(verified_map.values(),key=lambda x:x.get("score",0),reverse=True)[:80]
    evidence=sorted(evidence,key=lambda x:x.get("score",0),reverse=True)[:120]
    chains=sorted(chains,key=lambda x:x.get("score",0) or 0,reverse=True)[:90]
    artifacts=sorted(artifacts,key=lambda x:(x.get("exists",False),x.get("score",0),x.get("size",0)),reverse=True)[:800]
    recipes=sorted(recipes,key=lambda x:x.get("score",0),reverse=True)[:140]
    exact=[f for f in flags if "ctf_cs{" in f.get("flag","").lower()]
    workflow=[]
    if exact: workflow.append({"priority":100,"step":"Submit/check top strict ctf_cs flag.","why":"Primary contest format candidate survived strict filters."})
    elif answers: workflow.append({"priority":96,"step":"Open Answer Candidates.","why":"No strict flag found; likely answer may be a word/hash/coordinate/key/OCR result."})
    if recipes: workflow.append({"priority":92,"step":"Open Recipes tab and follow top recipe.","why":"Recipe Engine picked likely solve paths."})
    if artifacts: workflow.append({"priority":90,"step":"Open Artifacts / Visual Lab outputs.","why":"Generated/transformed/extracted files are collected with open/copy controls."})
    if evidence: workflow.append({"priority":88,"step":"Open Evidence Board top item.","why":"Noisy candidates are hidden."})
    priority=sorted([{"file":r.get("rel"),"kind":r.get("kind"),"flags":len(r.get("flags",[])),"answers":len(r.get("answer_candidates",[])),"verified":len(r.get("verified_flags_visible",[])),"recipes":len(r.get("recipe_runs",[])),"artifacts":len(r.get("artifacts",[])),"findings":len(r.get("findings",[])),"chains":len(r.get("chain_results",[])),"top_score":max([x.get("score",0) for x in r.get("findings",[])]+[0])} for r in reports],key=lambda x:(x["flags"],x["answers"],x["verified"],x["recipes"],x["top_score"],x["artifacts"]),reverse=True)[:120]
    summary={"flags":flags,"answer_candidates":answers,"verified_flags":verified_all,"exact_flags":exact,"kinds":kinds,"evidence_board":evidence,"top_findings":evidence,"top_chains":chains,"agents":sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:160],"transformations":sorted(transforms,key=lambda x:x.get("score",0),reverse=True)[:240],"artifacts":artifacts,"recipes":recipes,"artifact_graphs":graphs[:120],"verifyloops":verifyloops[:160],"hypotheses":workflowbrain_project_hypotheses(reports) if "workflowbrain_project_hypotheses" in globals() else [],"workflow_steps":sorted(workflow+actions,key=lambda x:x.get("priority",0),reverse=True)[:160],"missing_tools":sorted(set(missing))[:100],"priority_files":priority}
    summary["health"]=cl_project_health(reports, summary) if "cl_project_health" in globals() else {"status":"solved" if flags else ("answer_candidates" if answers else "needs_review")}
    summary["unresolved_plan"]=cl_unresolved_plan(reports) if "cl_unresolved_plan" in globals() else []
    try:
        paths=[Path(r.get("path","")) for r in reports if r.get("path")]
        root=paths[0].parents[1] if paths and len(paths[0].parents)>1 else BASE
        if "cl_make_project_brief" in globals():
            brief=cl_make_project_brief(root, reports, summary)
            if brief: summary["artifacts"].insert(0,brief)
    except Exception: pass
    return summary
def cl_run_self_checks():
    """v30 fast regression checks: strict ctf_cs + non-format answer candidates + visual artifacts."""
    results=[]; temp_ids=[]
    import base64 as _b64
    try:
        # Direct multi-layer strict flag.
        flag=b"ctf_cs{selfcheck_multi_layer_ok}"
        l1=_b64.b64encode(flag).decode(); l2=l1.encode().hex(); l3=_b64.b64encode(l2.encode()).decode()
        direct=dp_raw_transform_bfs("selfcheck","blob="+l3,max_depth=6,beam=60)
        results.append({"name":"direct_multi_layer_base64_hex_base64","ok":"ctf_cs{selfcheck_multi_layer_ok}" in json.dumps(direct),"flags":cl_clean_flag_list(json.dumps(direct)) if "cl_clean_flag_list" in globals() else vf_primary_flags(json.dumps(direct))})
        # Direct XOR.
        plain=b"noise::ctf_cs{selfcheck_xor_crib_ok}::end"; key=b"k3y"
        enc=bytes(b ^ key[i%len(key)] for i,b in enumerate(plain))
        xo=dp_xor_key_from_crib(enc)
        results.append({"name":"direct_aligned_repeating_xor_crib","ok":"ctf_cs{selfcheck_xor_crib_ok}" in json.dumps(xo),"flags":vf_primary_flags(json.dumps(xo))})
        # Non-format answer candidate.
        fake_report={"flags":[],"verified_flags":[],"strings":["atsakymas: berzas42"],"outputs":[{"ok":True,"out":"atsakymas: berzas42"}],"chain_results":[],"previews":[],"artifacts":[]}
        ans=vf_collect_answer_candidates(fake_report)
        results.append({"name":"non_format_answer_candidate","ok":any("berzas42" in a.get("value","") for a in ans),"answers":ans[:5]})
        # Full project strict flag.
        flag=b"ctf_cs{selfcheck_project_ok}"
        l1=_b64.b64encode(flag).decode(); l2=l1.encode().hex(); l3=_b64.b64encode(l2.encode()).decode()
        pid=cl_build_temp_project(BASE,"project_multi",[("multi.txt","format ctf_cs{...}\nblob="+l3,"text")])
        temp_ids.append(pid); analyze_project(pid); rep=jread(report_path(pid),{})
        results.append({"name":"project_end_to_end_multi_layer","ok":"ctf_cs{selfcheck_project_ok}" in [x.get("flag") for x in rep.get("summary",{}).get("flags",[])],"flags":[x.get("flag") for x in rep.get("summary",{}).get("flags",[])]})
        passed=sum(1 for r in results if r["ok"])
        return {"ok":passed==len(results),"passed":passed,"total":len(results),"results":results}
    finally:
        for pid in temp_ids:
            try: shutil.rmtree(pdir(pid), ignore_errors=True)
            except Exception: pass
def vf_collect_answer_candidates(report):
    cands=[]
    for f in report.get("flags",[]):
        vf_add_answer(cands, f, "promoted flag", "strict ctf_cs candidate", 250)
    for v in report.get("verified_flags",[]):
        vf_add_answer(cands, v.get("flag",""), "verified_flags", "; ".join(v.get("reasons",[])[:3]), int(v.get("score",0)//4))
    joined="\n".join(report.get("strings",[])[:1200])+"\n"+"\n".join((o.get("out") or "")[:6000] for o in report.get("outputs",[])[:100])
    for alt in vf_alt_ctf_candidates(joined):
        cands.append({"value":alt,"source":"alternate_ctf_like","why":"Not promoted because this toolkit promotes only ctf_cs{...}; keep as alternate answer candidate.","score":90})
    # Direct statement/output answer lines.
    for srcname, txt in [("strings_outputs", joined)]:
        for line in str(txt).splitlines()[:2000]:
            line=line.strip()
            low=line.lower()
            if not (4 <= len(line) <= 240):
                continue
            if any(k in low for k in ["answer","atsakymas","ats:","raktas","key","secret","slapta","password","pass","code","kodas"]):
                vf_add_answer(cands, line, srcname, "answer-like line from strings/tool output", 35)
                # Extract RHS after separators too.
                m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|password|pass|code|kodas)\s*[:=]\s*(.+)$", line, re.I)
                if m:
                    vf_add_answer(cands, m.group(1).strip(), srcname, "value after answer/key separator", 70)
    for c in report.get("chain_results",[])[:90]:
        out=(c.get("output") or "")[:3500]
        for f in vf_primary_flags(out, limit=5):
            vf_add_answer(cands, f, "chain:"+str(c.get("type","")), "decoded/derived output", int(c.get("score",0)//4)+80)
        for line in out.splitlines()[:100]:
            line=line.strip()
            if 4 <= len(line) <= 180 and any(k in line.lower() for k in ["answer","atsakymas","ats:","raktas","key","secret","slapta","password","pass","code","kodas"]):
                vf_add_answer(cands, line, "chain_context:"+str(c.get("type","")), "answer-like context line", 35)
                m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|password|pass|code|kodas)\s*[:=]\s*(.+)$", line, re.I)
                if m:
                    vf_add_answer(cands, m.group(1).strip(), "chain_value:"+str(c.get("type","")), "value after answer/key separator", 70)
    for p in report.get("previews",[])[:120]:
        txt=((p.get("ocr","") or "")+"\n"+(p.get("qr","") or "")).strip()
        for f in vf_primary_flags(txt, limit=4):
            vf_add_answer(cands, f, "visual_ocr_qr:"+str(p.get("name","")), "OCR/QR over generated visual artifact", int(p.get("score",0)//4)+90)
        for line in txt.splitlines()[:60]:
            line=line.strip()
            if 3 <= len(line) <= 140:
                vf_add_answer(cands, line, "visual_ocr:"+str(p.get("name","")), "OCR text; may be non-flag answer", int(p.get("score",0)//8)+20)
    for a in report.get("artifacts",[])[:200]:
        p=Path(a.get("path",""))
        try:
            if p.exists() and p.is_file() and p.stat().st_size<800000 and (p.suffix.lower() in [".txt",".json",".log",".md",".csv",".xml"] or any(x in p.name.lower() for x in ["ocr","decoded","answer","secret","key","brief"])):
                txt=p.read_text(encoding="utf-8",errors="ignore")[:12000]
                for f in vf_primary_flags(txt, limit=5):
                    vf_add_answer(cands, f, "artifact:"+a.get("kind",""), "artifact text", int(a.get("score",0)//3)+80)
                for line in txt.splitlines()[:160]:
                    line=line.strip()
                    if 4 <= len(line) <= 180 and any(k in line.lower() for k in ["answer","atsakymas","ats:","raktas","key","secret","slapta","password","pass","code","kodas"]):
                        vf_add_answer(cands, line, "artifact_context:"+a.get("kind",""), "answer-like artifact line", int(a.get("score",0)//5)+25)
                        m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|password|pass|code|kodas)\s*[:=]\s*(.+)$", line, re.I)
                        if m:
                            vf_add_answer(cands, m.group(1).strip(), "artifact_value:"+a.get("kind",""), "value after separator", int(a.get("score",0)//5)+60)
        except Exception:
            pass
    out=[]; seen=set()
    for x in sorted(cands,key=lambda z:z.get("score",0),reverse=True):
        k=x["value"].lower()
        if k not in seen:
            seen.add(k); out.append(x)
    return out[:160]
def cl_clean_flag_list(text):
    vals=vf_primary_flags(str(text or ""), limit=80)
    return [v for v in vals if smartsolve_strict_target_flag_ok(v)][:20]
def vf_visual_lab(path, root, report):
    """Fast visual filter gallery. OCR is bounded and never re-run during summary."""
    arts=[]; previews=[]
    try:
        im=Image.open(path).convert("RGB")
    except Exception:
        return [], []
    outdir=root/"generated"/"visualforge"/safe(report.get("name",Path(path).stem))
    proc=im.copy()
    if max(proc.size)>1600:
        proc.thumbnail((1600,1600))
    def add(name, img, score=30, note=""):
        art=vf_save_image(root, report, outdir, name, img.convert("RGB") if getattr(img,"mode","RGB")!="RGB" else img, score, note or name)
        if art:
            arts.append(art)
            previews.append({"name":"vf_"+name,"url":art["url"],"path":art["path"],"score":score,"ocr":"","qr":"","flags":[]})
    gray=ImageOps.grayscale(proc)
    add("00_preview", proc.copy(), 40, "preview")
    # Rotations / flips for sideways text.
    for name,img in [("rot90",proc.rotate(90,expand=True)),("rot180",proc.rotate(180,expand=True)),("rot270",proc.rotate(270,expand=True)),("flip_lr",ImageOps.mirror(proc)),("flip_tb",ImageOps.flip(proc))]:
        add("orientation_"+name,img,65,"rotation/flip")
    # Channels and HSV.
    try:
        arr=np.array(proc)
        for idx,ch in enumerate(["R","G","B"]):
            chimg=Image.fromarray(arr[:,:,idx]).convert("L")
            add(f"channel_{ch}",chimg,40,f"{ch} channel")
            add(f"channel_{ch}_autocontrast",ImageOps.autocontrast(chimg),55,f"{ch} autocontrast")
            add(f"channel_{ch}_invert",ImageOps.invert(chimg),48,f"{ch} invert")
        hsv=proc.convert("HSV")
        for nm,img in zip(["HSV_H","HSV_S","HSV_V"],hsv.split()):
            add(nm,ImageOps.autocontrast(img),55,nm)
    except Exception:
        pass
    # Strong filters for hidden letters.
    base_filters=[
        ("gray",gray,35),("gray_autocontrast",ImageOps.autocontrast(gray),55),
        ("invert",ImageOps.invert(gray),45),
        ("edges",gray.filter(ImageFilter.FIND_EDGES),60),
        ("edges_autocontrast",ImageOps.autocontrast(gray.filter(ImageFilter.FIND_EDGES)),72),
        ("emboss",gray.filter(ImageFilter.EMBOSS),55),
        ("sharpen",gray.filter(ImageFilter.SHARPEN),45),
    ]
    for name,img,score in base_filters:
        add(name,img,score,name)
    try:
        for r in [2,5,9,15]:
            blur=gray.filter(ImageFilter.GaussianBlur(radius=r))
            diff=ImageChops.difference(gray,blur)
            add(f"highpass_blur{r}",ImageOps.autocontrast(diff),75,"high-pass blur difference")
    except Exception:
        pass
    for t in [40,64,90,110,128,150,180,210]:
        bw=gray.point(lambda x,thr=t: 255 if x>thr else 0)
        add(f"threshold_{t}",bw,50,f"threshold {t}")
    try:
        for bits in [2,3,4]:
            add(f"posterize_{bits}",ImageOps.posterize(proc,bits),55,f"posterize {bits}")
        for thr in [64,96,128,160]:
            add(f"solarize_{thr}",ImageOps.solarize(proc,thr),50,f"solarize {thr}")
    except Exception:
        pass
    for c in [1.5,2.2,3.2]:
        try: add(f"contrast_{str(c).replace('.','_')}",ImageEnhance.Contrast(proc).enhance(c),55,"contrast sweep")
        except Exception: pass
    for b in [0.55,0.75,1.25,1.6]:
        try: add(f"brightness_{str(b).replace('.','_')}",ImageEnhance.Brightness(proc).enhance(b),48,"brightness sweep")
        except Exception: pass
    # Contact sheet.
    try:
        selected=arts[:60]
        cols=4; tw,th=260,210; rows=max(1,math.ceil(len(selected)/cols))
        sheet=Image.new("RGB",(cols*tw,rows*th),(5,10,5))
        for i,a in enumerate(selected):
            p=Path(a["path"])
            img=Image.open(p).convert("RGB")
            img.thumbnail((240,170))
            tile=Image.new("RGB",(tw,th),(12,25,15))
            tile.paste(img,(10,10))
            sheet.paste(tile,((i%cols)*tw,(i//cols)*th))
        art=vf_save_image(root,report,outdir,"00_visualforge_contact_sheet",sheet,100,"VisualForge contact sheet")
        if art:
            arts.insert(0,art)
            previews.insert(0,{"name":"vf_contact_sheet","url":art["url"],"path":art["path"],"score":100,"ocr":"","qr":"","flags":[]})
    except Exception:
        pass
    # Bounded OCR/QR: only top few, short timeout. No repeated OCR in summaries.
    ocr_targets=previews[:10]
    for item in ocr_targets:
        p=Path(item.get("path",""))
        if not p.exists(): continue
        if exists("zbarimg"):
            try:
                q=run(["zbarimg","--quiet",str(p)],3).get("out","")
                item["qr"]=q[:1000]; item["flags"]+=vf_primary_flags(q,limit=5)
                if q.strip(): item["score"]=item.get("score",0)+80
            except Exception: pass
        if exists("tesseract"):
            try:
                o=run(["tesseract",str(p),"stdout"],4).get("out","")
                item["ocr"]=o[:2000]; item["flags"]+=vf_primary_flags(o,limit=5)
                if o.strip(): item["score"]=item.get("score",0)+min(60,score_text(o))
            except Exception: pass
    return arts, sorted(previews,key=lambda x:x.get("score",0),reverse=True)[:80]
def vf_postprocess(report, root):
    # Generate VisualForge only once. Summaries must not re-run OCR/filter generation.
    if report.get("kind")=="image":
        has_vf=bool(report.get("_visualforge_done")) or any("VisualForge" in str(a.get("source","")) for a in report.get("artifacts",[]))
        if not has_vf:
            arts, previews = vf_visual_lab(Path(report.get("path","")), root, report)
            existing=set(a.get("path") for a in report.get("artifacts",[]))
            for a in arts:
                if a.get("path") not in existing:
                    report.setdefault("artifacts",[]).append(a); existing.add(a.get("path"))
            report.setdefault("previews",[]).extend(previews)
            report["_visualforge_done"]=True
    try:
        smartsolve_postprocess(report, root)
    except Exception:
        try: stableworkbench_apply_report_postprocess(report, root)
        except Exception: pass
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    return report
def project_summary(reports, meta):
    # Summary must stay lightweight; do not regenerate VisualForge.
    flags=[]; verified_map={}; kinds={}; evidence=[]; chains=[]; actions=[]; missing=[]; agents=[]; transforms=[]; verifyloops=[]; artifacts=[]; recipes=[]; graphs=[]; answers=[]
    for r in reports:
        try:
            # Only answer candidates and light postprocess; no VisualForge generation if already done.
            if r.get("kind")!="image" or any("VisualForge" in str(a.get("source","")) for a in r.get("artifacts",[])):
                vf_postprocess(r, Path(r.get("path","")).parents[1] if r.get("path") else BASE)
            else:
                report_root=Path(r.get("path","")).parents[1] if r.get("path") else BASE
                try: smartsolve_postprocess(r, report_root)
                except Exception: pass
                r["answer_candidates"]=vf_collect_answer_candidates(r)
        except Exception:
            pass
        kinds[r.get("kind","?")]=kinds.get(r.get("kind","?"),0)+1
        for v in r.get("verified_flags_visible", []):
            key=(v.get("flag") or "").lower()
            vv={"file":r.get("rel"),**v}
            if key and (key not in verified_map or vv.get("score",0)>verified_map[key].get("score",0)): verified_map[key]=vv
        for f in r.get("flags", []):
            if smartsolve_strict_target_flag_ok(f): flags.append({"file":r.get("rel"),"flag":f,"score":999,"status":"promoted"})
        for ans in r.get("answer_candidates",[])[:80]: answers.append({"file":r.get("rel"),**ans})
        for f in r.get("findings",[])[:60]:
            if not is_noisy_candidate_text(f.get("value",""), f.get("why",""), f.get("type","")): evidence.append({"file":r.get("rel"),**f})
        for c in r.get("chain_results",[])[:30]:
            out=(c.get("output","") or "")[:900]
            if c.get("score",0)>70 and not is_noisy_candidate_text(out,c.get("type",""),"chain"):
                chains.append({"file":r.get("rel"),"type":c.get("type"),"source":c.get("chain_source"),"score":c.get("score"),"output":out})
        for s in r.get("next_steps",[])[:10]: actions.append({"file":r.get("rel"),**s})
        for a in r.get("agent_runs",[])[:12]: agents.append({"file":r.get("rel"),"kind":r.get("kind"),**a})
        for t in r.get("transformations",[])[:50]: transforms.append({"file":r.get("rel"),**t})
        if r.get("verifyloop"): verifyloops.append({"file":r.get("rel"),"kind":r.get("kind"),**r.get("verifyloop",{})})
        for art in r.get("artifacts",[])[:260]: artifacts.append(art)
        for rec in r.get("recipe_runs",[])[:12]: recipes.append({"file":r.get("rel"),"kind":r.get("kind"),**rec})
        if r.get("artifact_graph"): graphs.append({"file":r.get("rel"),"graph":r.get("artifact_graph")})
        for o in r.get("outputs",[]):
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
    answers=sorted(ans_map.values(),key=lambda x:x.get("score",0),reverse=True)[:180]
    verified_all=sorted(verified_map.values(),key=lambda x:x.get("score",0),reverse=True)[:80]
    evidence=sorted(evidence,key=lambda x:x.get("score",0),reverse=True)[:120]
    chains=sorted(chains,key=lambda x:x.get("score",0) or 0,reverse=True)[:90]
    artifacts=sorted(artifacts,key=lambda x:(x.get("exists",False),x.get("score",0),x.get("size",0)),reverse=True)[:800]
    recipes=sorted(recipes,key=lambda x:x.get("score",0),reverse=True)[:140]
    exact=[f for f in flags if "ctf_cs{" in f.get("flag","").lower()]
    workflow=[]
    if exact: workflow.append({"priority":100,"step":"Submit/check top strict ctf_cs flag.","why":"Primary contest format candidate survived strict filters."})
    elif answers: workflow.append({"priority":96,"step":"Open Answer Candidates.","why":"No strict flag found; likely answer may be a word/hash/coordinate/key/OCR result."})
    if recipes: workflow.append({"priority":92,"step":"Open Recipes tab and follow top recipe.","why":"Recipe Engine picked likely solve paths."})
    if artifacts: workflow.append({"priority":90,"step":"Open Artifacts / Visual Lab outputs.","why":"Generated/transformed/extracted files are collected with open/copy controls."})
    if evidence: workflow.append({"priority":88,"step":"Open Evidence Board top item.","why":"Noisy candidates are hidden."})
    priority=sorted([{"file":r.get("rel"),"kind":r.get("kind"),"flags":len(r.get("flags",[])),"answers":len(r.get("answer_candidates",[])),"verified":len(r.get("verified_flags_visible",[])),"recipes":len(r.get("recipe_runs",[])),"artifacts":len(r.get("artifacts",[])),"findings":len(r.get("findings",[])),"chains":len(r.get("chain_results",[])),"top_score":max([x.get("score",0) for x in r.get("findings",[])]+[0])} for r in reports],key=lambda x:(x["flags"],x["answers"],x["verified"],x["recipes"],x["top_score"],x["artifacts"]),reverse=True)[:120]
    summary={"flags":flags,"answer_candidates":answers,"verified_flags":verified_all,"exact_flags":exact,"kinds":kinds,"evidence_board":evidence,"top_findings":evidence,"top_chains":chains,"agents":sorted(agents,key=lambda x:x.get("score",0),reverse=True)[:160],"transformations":sorted(transforms,key=lambda x:x.get("score",0),reverse=True)[:240],"artifacts":artifacts,"recipes":recipes,"artifact_graphs":graphs[:120],"verifyloops":verifyloops[:160],"hypotheses":workflowbrain_project_hypotheses(reports) if "workflowbrain_project_hypotheses" in globals() else [],"workflow_steps":sorted(workflow+actions,key=lambda x:x.get("priority",0),reverse=True)[:160],"missing_tools":sorted(set(missing))[:100],"priority_files":priority}
    summary["health"]=cl_project_health(reports, summary) if "cl_project_health" in globals() else {"status":"solved" if flags else ("answer_candidates" if answers else "needs_review")}
    summary["unresolved_plan"]=cl_unresolved_plan(reports) if "cl_unresolved_plan" in globals() else []
    return summary
STRICT_PRIMARY_FLAG_RE = re.compile(r"\bctf_cs\{[A-Za-z0-9][A-Za-z0-9_\-:.+]{4,120}\}", re.I)
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
def fast_flag_matches(text, limit=20, scan_limit=9000):
    return vf_primary_flags(text, limit=limit, scan_limit=scan_limit)
def cl_clean_flag_list(text):
    return vf_primary_flags(str(text or ""), limit=20)
def cl_run_self_checks():
    """v30 fast regression checks with strict display."""
    results=[]; temp_ids=[]
    import base64 as _b64
    try:
        flag=b"ctf_cs{selfcheck_multi_layer_ok}"
        l1=_b64.b64encode(flag).decode(); l2=l1.encode().hex(); l3=_b64.b64encode(l2.encode()).decode()
        direct=dp_raw_transform_bfs("selfcheck","blob="+l3,max_depth=6,beam=60)
        results.append({"name":"direct_multi_layer_base64_hex_base64","ok":"ctf_cs{selfcheck_multi_layer_ok}" in json.dumps(direct),"flags":cl_clean_flag_list(json.dumps(direct))})
        plain=b"noise::ctf_cs{selfcheck_xor_crib_ok}::end"; key=b"k3y"
        enc=bytes(b ^ key[i%len(key)] for i,b in enumerate(plain))
        xo=dp_xor_key_from_crib(enc)
        results.append({"name":"direct_aligned_repeating_xor_crib","ok":"ctf_cs{selfcheck_xor_crib_ok}" in json.dumps(xo),"flags":cl_clean_flag_list(json.dumps(xo))})
        fake_report={"flags":[],"verified_flags":[],"strings":["atsakymas: berzas42"],"outputs":[{"ok":True,"out":"atsakymas: berzas42"}],"chain_results":[],"previews":[],"artifacts":[]}
        ans=vf_collect_answer_candidates(fake_report)
        results.append({"name":"non_format_answer_candidate","ok":any("berzas42" in a.get("value","") for a in ans),"answers":ans[:5]})
        flag=b"ctf_cs{selfcheck_project_ok}"
        l1=_b64.b64encode(flag).decode(); l2=l1.encode().hex(); l3=_b64.b64encode(l2.encode()).decode()
        pid=cl_build_temp_project(BASE,"project_multi",[("multi.txt","format ctf_cs{...}\nblob="+l3,"text")])
        temp_ids.append(pid); analyze_project(pid); rep=jread(report_path(pid),{})
        results.append({"name":"project_end_to_end_multi_layer","ok":"ctf_cs{selfcheck_project_ok}" in [x.get("flag") for x in rep.get("summary",{}).get("flags",[])],"flags":[x.get("flag") for x in rep.get("summary",{}).get("flags",[])]})
        passed=sum(1 for r in results if r["ok"])
        return {"ok":passed==len(results),"passed":passed,"total":len(results),"results":results}
    finally:
        for pid in temp_ids:
            try: shutil.rmtree(pdir(pid), ignore_errors=True)
            except Exception: pass
def rb_zip_manifest(zip_path):
    """Fast manifest using stdlib; returns category/challenge grouping."""
    out={"zip":str(zip_path),"exists":Path(zip_path).exists(),"files":[],"challenges":[],"categories":{}}
    if not Path(zip_path).exists():
        return out
    try:
        with zipfile.ZipFile(zip_path) as z:
            for inf in z.infolist():
                if inf.is_dir(): 
                    continue
                parts=Path(inf.filename).parts
                if len(parts)<2:
                    cat="root"; ch="root"
                elif len(parts)>=3:
                    cat=parts[1]; ch=parts[2]
                else:
                    cat=parts[0]; ch=Path(inf.filename).parent.name or "root"
                rec={"name":inf.filename,"size":inf.file_size,"category":cat,"challenge":ch,"suffix":Path(inf.filename).suffix.lower()}
                out["files"].append(rec)
                key=f"{cat}/{ch}"
                out["categories"].setdefault(cat,0); out["categories"][cat]+=1
        groups={}
        for f in out["files"]:
            key=f["category"]+"/"+f["challenge"]
            groups.setdefault(key,{"category":f["category"],"challenge":f["challenge"],"files":[],"total_size":0})
            groups[key]["files"].append(f)
            groups[key]["total_size"]+=f["size"]
        out["challenges"]=sorted(groups.values(), key=lambda x:(x["category"],x["challenge"]))
        return out
    except Exception as e:
        out["error"]=str(e)
        return out
def rb_safe_extract_zip_selected(zip_path, dest_root, members):
    dest_root=Path(dest_root)
    dest_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as z:
        for m in members:
            # Prevent zip slip.
            target=dest_root/safe(Path(m).name)
            # Preserve subdirs lightly where useful.
            name=Path(m).name
            if not name:
                continue
            data=z.read(m)
            target.write_bytes(data)
def rb_group_members(zip_path):
    groups={}
    with zipfile.ZipFile(zip_path) as z:
        for inf in z.infolist():
            if inf.is_dir(): continue
            parts=Path(inf.filename).parts
            if len(parts)>=3:
                key=(parts[1],parts[2])
            elif len(parts)>=2:
                key=(parts[0],Path(inf.filename).parent.name or "root")
            else:
                key=("root","root")
            groups.setdefault(key,[]).append(inf.filename)
    return groups
def rb_batch_zip_import(zip_path, auto_start=False, max_projects=80):
    """Create one project per challenge folder from a zip."""
    zip_path=Path(zip_path)
    manifest=rb_zip_manifest(zip_path)
    if not manifest.get("exists") or manifest.get("error"):
        return {"ok":False,"error":manifest.get("error","zip not found"),"manifest":manifest}
    created=[]
    groups=rb_group_members(zip_path)
    for (cat,ch),members in list(groups.items())[:max_projects]:
        # Skip weird empty groups.
        if not members: continue
        pid=uuid.uuid4().hex[:12]
        root=pdir(pid); fdir=root/"files"; fdir.mkdir(parents=True, exist_ok=True)
        title=f"{cat} / {ch}"
        meta={"id":pid,"title":title,"statement":"","category":cat,"created":now(),"file_count":len(members),"batch_source":str(zip_path),"batch_challenge":ch,"batch_category":cat}
        jwrite(meta_path(pid), meta)
        # Extract each member with sanitized but context-rich file names.
        with zipfile.ZipFile(zip_path) as z:
            for m in members:
                original=Path(m).name or safe(m)
                dest=fdir/safe(original)
                if dest.exists():
                    dest=fdir/(uuid.uuid4().hex[:4]+"_"+safe(original))
                dest.write_bytes(z.read(m))
        with LOCK:
            JOBS[pid]={"status":"created","progress":0,"stage":"Created from batch zip","updated":time.time()}
        log(pid,f"Batch project created from {zip_path.name}: {cat}/{ch}")
        if auto_start:
            with LOCK: JOBS[pid]["status"]="running"
            # Do not background here; caller endpoint schedules tasks.
        created.append({"id":pid,"title":title,"category":cat,"challenge":ch,"files":len(members)})
    return {"ok":True,"created":created,"manifest":{"categories":manifest.get("categories",{}),"challenge_count":len(manifest.get("challenges",[])),"file_count":len(manifest.get("files",[]))}}
def rb_textual_context_score(line):
    line=str(line or "").strip()
    low=line.lower()
    score=0
    if any(k in low for k in ["atsakymas","answer","raktas","key","slapta","secret","password","pass","kodas","code","flag","ctf_cs"]): score+=90
    if re.search(r"[A-Za-z0-9_\-:.+]{8,}", line): score+=20
    if re.fullmatch(r"[A-Fa-f0-9]{32,64}", line): score+=70
    if len(line)>200: score-=30
    return score
def vf_answer_score(text, source=""):
    s=str(text or "").strip()
    if not s or len(s)<3 or len(s)>320: return 0
    low=s.lower(); score=0
    if PRIMARY_FLAG_RE.search(s): score+=300
    if re.fullmatch(r"[a-fA-F0-9]{64}",s): score+=160
    if re.fullmatch(r"[a-fA-F0-9]{32,40}",s): score+=110
    if re.fullmatch(r"-?\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+",s): score+=130
    if re.fullmatch(r"[A-Za-z0-9_\-:.+]{5,140}",s): score+=45
    # Lithuanian and CTF prompt clues.
    if any(k in low for k in ["answer","atsakymas","ats:","raktas","key","secret","slapta","password","slaptažodis","pass:","code","kodas","vartotojas","user","login","token"]): score+=70
    if any(k in low for k in ["surask","rask","įvesk","ivesk","pateik","flagas","vėliava","veliava"]): score+=35
    if any(w in low for w in ["sample","dummy","fake","placeholder","example","format","ctf_cs{...}"]): score-=130
    if "�" in s: score-=80
    if source and any(x in source.lower() for x in ["ocr","qr","artifact","chain"]): score+=20
    return score
def rb_decompress_file_artifacts(root, report, data):
    """Turn .gz/.bz2/.xz/zlib/raw compressed files into actual artifacts."""
    arts=[]
    path=Path(report.get("path",""))
    suffix=path.suffix.lower()
    candidates=[]
    try:
        if suffix==".gz":
            candidates.append(("gzip", gzip.decompress(data)))
        if suffix==".bz2":
            candidates.append(("bz2", bz2.decompress(data)))
        if suffix in [".xz",".lzma"]:
            candidates.append(("lzma", lzma.decompress(data)))
    except Exception:
        pass
    # Signature-based tries too.
    for name,func in [("gzip_sig",gzip.decompress),("bz2_sig",bz2.decompress),("lzma_sig",lzma.decompress),("zlib_sig",zlib.decompress)]:
        try:
            out=func(data)
            if out and len(out)>0:
                candidates.append((name,out))
        except Exception:
            pass
    seen=set()
    outdir=root/"generated"/"realbench_decompressed"/safe(report.get("name","file"))
    outdir.mkdir(parents=True,exist_ok=True)
    for kind,out in candidates[:6]:
        h=hashlib.sha256(out[:2000000]).hexdigest()[:12]
        if h in seen: continue
        seen.add(h)
        ext=".bin"
        txt=out[:2000].decode("utf-8","ignore")
        if txt and sum(1 for c in txt if c.isprintable() or c in "\n\r\t")/max(1,len(txt))>0.75:
            ext=".txt"
        p=outdir/(kind+"_"+h+ext)
        p.write_bytes(out)
        art={"kind":"decompressed_raw","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"RealBench decompressor","score":120 if vf_primary_flags(out.decode('utf-8','ignore')) else 75,"note":kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        arts.append(art)
    return arts
def rb_pcap_fallback_artifacts(root, report, data):
    """Useful pcap/pcapng fallback even without tshark: strings, hosts, HTTP-ish lines, DNS-ish labels."""
    if report.get("kind")!="pcap":
        return []
    outdir=root/"generated"/"realbench_pcap"/safe(report.get("name","pcap"))
    outdir.mkdir(parents=True, exist_ok=True)
    raw=data.decode("latin1","ignore")
    strings=py_strings(data,limit=10000)
    lines=[]
    for s in strings:
        low=s.lower()
        if any(k in low for k in ["http","host:","get ","post ","ctf","flag","token","secret","password","login","cookie","user-agent"]) or re.search(r"[a-z0-9.-]+\.[a-z]{2,}", low):
            lines.append(s)
    p=outdir/"pcap_fallback_strings.txt"
    p.write_text("\n".join(lines[:3000]),encoding="utf-8",errors="ignore")
    return [{"kind":"pcap_fallback","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"RealBench pcap fallback","score":95 if lines else 45,"note":"Extracted useful strings without tshark","exists":True,"size":p.stat().st_size,"file":report.get("rel","")}]
def rb_pyc_static_artifact(root, report, data):
    path=Path(report.get("path",""))
    if path.suffix.lower()!=".pyc":
        return []
    outdir=root/"generated"/"realbench_pyc"/safe(path.name); outdir.mkdir(parents=True,exist_ok=True)
    out=[]
    try:
        import marshal, dis, io
        # Common pyc header 16 bytes py3.7+; fallback 12.
        code=None
        for off in [16,12,8]:
            try:
                code=marshal.loads(data[off:])
                break
            except Exception:
                pass
        if code is not None:
            buf=io.StringIO()
            dis.dis(code,file=buf)
            p=outdir/"pyc_disassembly.txt"
            p.write_text(buf.getvalue(),encoding="utf-8",errors="ignore")
            out.append({"kind":"pyc_disassembly","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"RealBench pyc static","score":95,"note":"Static disassembly, no execution","exists":True,"size":p.stat().st_size,"file":report.get("rel","")})
            consts=[]
            def walk(c):
                for x in getattr(c,"co_consts",[]):
                    if isinstance(x,(str,bytes,int,float)):
                        consts.append(repr(x))
                    elif hasattr(x,"co_consts"):
                        walk(x)
            walk(code)
            p2=outdir/"pyc_constants.txt"
            p2.write_text("\n".join(consts[:2000]),encoding="utf-8",errors="ignore")
            out.append({"kind":"pyc_constants","name":p2.name,"path":str(p2),"url":"/api/raw?path="+str(p2),"source":"RealBench pyc static","score":110 if any("ctf" in c.lower() for c in consts) else 90,"note":"Constants from pyc, no execution","exists":True,"size":p2.stat().st_size,"file":report.get("rel","")})
    except Exception as e:
        p=outdir/"pyc_static_error.txt"; p.write_text(str(e),encoding="utf-8")
        out.append({"kind":"pyc_static_error","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"RealBench pyc static","score":20,"note":"pyc parse error","exists":True,"size":p.stat().st_size,"file":report.get("rel","")})
    return out
def rb_text_log_patterns(root, report, data):
    """For logs/text tasks: extract time anomalies, hashes, IPs, URLs, answer-like lines."""
    if report.get("kind") not in ["text","generic"] and Path(report.get("path","")).suffix.lower() not in [".log",".txt",".csv",".json"]:
        return []
    txt=data.decode("utf-8","ignore")
    if not txt.strip():
        return []
    lines=txt.splitlines()
    picks=[]
    pats=[
        re.compile(r"\bctf_cs\{[^}\n\r]{1,180}\}",re.I),
        re.compile(r"\b[A-Fa-f0-9]{32,64}\b"),
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        re.compile(r"https?://[^\s'\"<>]+"),
        re.compile(r"\b(?:answer|atsakymas|raktas|key|secret|slapta|password|kodas|code)\b.*",re.I),
        re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b"),
    ]
    for i,line in enumerate(lines[:20000]):
        if any(p.search(line) for p in pats):
            ctx="\n".join(lines[max(0,i-2):min(len(lines),i+3)])
            picks.append(ctx)
    if not picks:
        return []
    outdir=root/"generated"/"realbench_text"/safe(report.get("name","text")); outdir.mkdir(parents=True,exist_ok=True)
    p=outdir/"interesting_contexts.txt"
    p.write_text("\n---\n".join(picks[:1000]),encoding="utf-8",errors="ignore")
    return [{"kind":"text_interesting_contexts","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"RealBench text/log extractor","score":90,"note":"Interesting contexts from text/log","exists":True,"size":p.stat().st_size,"file":report.get("rel","")}]
def rb_enhance_report(root, report, data):
    arts=[]
    arts += rb_decompress_file_artifacts(root, report, data)
    arts += rb_pcap_fallback_artifacts(root, report, data)
    arts += rb_pyc_static_artifact(root, report, data)
    arts += rb_text_log_patterns(root, report, data)
    if arts:
        existing=set(a.get("path") for a in report.get("artifacts",[]))
        for a in arts:
            if a.get("path") not in existing:
                report.setdefault("artifacts",[]).append(a)
                report.setdefault("transformations",[]).append(a)
                existing.add(a.get("path"))
    return report
def analyze_file(pid,path,root,i,total):
    progress(pid,min(94,int((i/max(1,total))*84)+6),f"Analyzing {path.name}")
    data=readbytes(path)
    fileout=run(["file",str(path)],8).get("out","") if exists("file") else ""
    kind=detect_kind(path,fileout)
    # Improve kind from suffix.
    suf=path.suffix.lower()
    if suf in [".pcap",".pcapng"]: kind="pcap"
    if suf==".pyc": kind="python_bytecode"
    if suf in [".txt",".log",".csv",".json",".md"]: kind="text"
    ss=py_strings(data)
    rep={"id":uuid.uuid4().hex[:10],"name":path.name,"path":str(path),"rel":str(path.relative_to(root)),"size":path.stat().st_size,"entropy":entropy(data[:2_000_000]),"kind":kind,"file":fileout,"fingerprint":{"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest()},"flags":list(dict.fromkeys(x for x in vf_primary_flags(data.decode('utf-8','ignore'),limit=40))),"strings":ss[:900],"outputs":[],"previews":[],"commands":[],"extracted":[],"expert_contexts":[],"decoders":[],"chain_results":[],"intermediate_files":[],"findings":[],"next_steps":[],"hypotheses":[],"structured_clues":[],"agent_runs":[],"agent_files":[],"transformations":[],"verifyloop":{},"verified_flags":[],"promoted_children":[],"artifacts":[],"recipe_runs":[],"artifact_graph":{},"candidate_health":{},"answer_candidates":[]}
    if kind=="archive":
        rep["extracted"]=extract_archive(path,root/"files")
    if kind=="image":
        pv,outs=image_lab(path,root)
        rep["previews"]+=pv; rep["outputs"]+=outs
        for v in pv:
            for f in v.get("flags",[]):
                if f.lower().startswith("ctf_cs{") and f not in rep["flags"]: rep["flags"].append(f)
    if kind=="media" and exists("ffmpeg"):
        spdir=root/"generated"/"media"/path.stem; spdir.mkdir(parents=True,exist_ok=True); sp=spdir/"spectrogram.png"
        r=run(["ffmpeg","-y","-i",str(path),"-lavfi","showspectrumpic=s=1600x900",str(sp)],45)
        rep["outputs"].append({"tool":"spectrogram","ok":r["ok"],"cmd":r["cmd"],"out":r["out"]})
        if sp.exists(): rep["previews"].append({"name":"spectrogram","url":"/api/raw?path="+str(sp),"path":str(sp),"score":15})
    # RealBench pre-artifacts before decode so they feed answer candidates.
    rb_enhance_report(root, rep, data)
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
    if "deeppattern_enhance" in globals(): deeppattern_enhance(rep,root,data)
    rb_enhance_report(root, rep, data)
    apply_verified_flags(rep)
    verifyloop_promote_artifacts(root,rep)
    rep["findings"]=rank_findings(rep)
    rep["next_steps"]=next_steps(rep)
    vf_postprocess(rep,root)
    return rep
def rb_batch_summary():
    projects=[]
    for d in sorted([x for x in PROJECTS.iterdir() if x.is_dir()], reverse=True):
        meta=jread(d/"project.json",{})
        rep=jread(d/"report.json",{})
        if not meta.get("batch_source"): 
            continue
        summ=rep.get("summary",{})
        projects.append({
            "id":meta.get("id"),
            "title":meta.get("title"),
            "category":meta.get("batch_category") or meta.get("category"),
            "challenge":meta.get("batch_challenge"),
            "flags":[x.get("flag") for x in summ.get("flags",[])],
            "answers":[x.get("value") for x in summ.get("answer_candidates",[])[:5]],
            "status":summ.get("health",{}).get("status","done" if rep else meta.get("runtime_status","idle")),
            "artifacts":len(summ.get("artifacts",[])),
            "recipes":len(summ.get("recipes",[])),
            "progress":JOBS.get(meta.get("id"),{}).get("progress",100 if rep else 0)
        })
    solved=sum(1 for p in projects if p["flags"])
    answered=sum(1 for p in projects if p["answers"])
    return {"projects":projects,"total":len(projects),"with_flags":solved,"with_answers":answered,"unresolved":len(projects)-solved-answered}
async def batch_import_zip(background_tasks:BackgroundTasks, files:UploadFile=File(...), auto_start:str=Form("false")):
    batch_dir=BASE/"batches"; batch_dir.mkdir(exist_ok=True)
    zp=batch_dir/safe(files.filename)
    zp.write_bytes(await files.read())
    res=rb_batch_zip_import(zp, auto_start=auto_start.lower()=="true")
    if res.get("ok") and auto_start.lower()=="true":
        for item in res.get("created",[]):
            background_tasks.add_task(analyze_project,item["id"])
    return res
async def batch_import_zip_path(background_tasks:BackgroundTasks, path:str=Form(...), auto_start:str=Form("false")):
    res=rb_batch_zip_import(Path(path), auto_start=auto_start.lower()=="true")
    if res.get("ok") and auto_start.lower()=="true":
        for item in res.get("created",[]):
            background_tasks.add_task(analyze_project,item["id"])
    return res
def batch_summary_endpoint():
    return rb_batch_summary()
def realbench_manifest_endpoint(path:str="/mnt/data/Cyber Sprint 2026 1 etapas.zip"):
    return rb_zip_manifest(Path(path))
def vf_collect_answer_candidates(report):
    cands=[]
    for f in report.get("flags",[])[:50]:
        vf_add_answer(cands, f, "promoted flag", "strict ctf_cs candidate", 250)
    for v in report.get("verified_flags",[])[:80]:
        vf_add_answer(cands, v.get("flag",""), "verified_flags", "; ".join(v.get("reasons",[])[:3]), int(v.get("score",0)//4))
    joined="\n".join(report.get("strings",[])[:900])+"\n"+"\n".join((o.get("out") or "")[:4000] for o in report.get("outputs",[])[:60])
    for alt in vf_alt_ctf_candidates(joined,limit=20):
        cands.append({"value":alt,"source":"alternate_ctf_like","why":"Not promoted because only ctf_cs{...} is auto-promoted.","score":90})
    for line in joined.splitlines()[:1500]:
        line=line.strip()
        low=line.lower()
        if not (4 <= len(line) <= 240): continue
        if any(k in low for k in ["answer","atsakymas","ats:","raktas","key","secret","slapta","slaptažodis","password","pass","code","kodas","token"]):
            vf_add_answer(cands,line,"strings_outputs","answer-like line",35)
            m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|password|pass|code|kodas|token)\s*[:=]\s*(.+)$",line,re.I)
            if m: vf_add_answer(cands,m.group(1).strip(),"strings_outputs","value after answer/key separator",70)
    for c in report.get("chain_results",[])[:45]:
        out=(c.get("output") or "")[:3000]
        for f in vf_primary_flags(out,limit=4):
            vf_add_answer(cands,f,"chain:"+str(c.get("type","")),"decoded output",int(c.get("score",0)//4)+80)
        for line in out.splitlines()[:50]:
            line=line.strip(); low=line.lower()
            if 4<=len(line)<=180 and any(k in low for k in ["answer","atsakymas","ats:","raktas","key","secret","slapta","slaptažodis","password","pass","code","kodas","token"]):
                vf_add_answer(cands,line,"chain_context:"+str(c.get("type","")),"answer-like context",35)
                m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|password|pass|code|kodas|token)\s*[:=]\s*(.+)$",line,re.I)
                if m: vf_add_answer(cands,m.group(1).strip(),"chain_value:"+str(c.get("type","")),"value after separator",70)
    for p in report.get("previews",[])[:60]:
        txt=((p.get("ocr","") or "")+"\n"+(p.get("qr","") or "")).strip()
        for f in vf_primary_flags(txt,limit=4):
            vf_add_answer(cands,f,"visual_ocr_qr:"+str(p.get("name","")),"OCR/QR",int(p.get("score",0)//4)+90)
        for line in txt.splitlines()[:25]:
            line=line.strip()
            if 3<=len(line)<=140: vf_add_answer(cands,line,"visual_ocr:"+str(p.get("name","")),"OCR text",int(p.get("score",0)//8)+20)
    for a in report.get("artifacts",[])[:80]:
        pathstr=a.get("path","")
        if not pathstr: continue
        p=Path(pathstr)
        try:
            if not p.exists() or not p.is_file(): continue
            if p.stat().st_size>=500000: continue
            if not (p.suffix.lower() in [".txt",".json",".log",".md",".csv",".xml"] or any(x in p.name.lower() for x in ["ocr","decoded","answer","secret","key","brief","strings","fallback","constants"])):
                continue
            txt=p.read_text(encoding="utf-8",errors="ignore")[:8000]
            for f in vf_primary_flags(txt,limit=4):
                vf_add_answer(cands,f,"artifact:"+a.get("kind",""),"artifact text",int(a.get("score",0)//3)+80)
            for line in txt.splitlines()[:80]:
                line=line.strip(); low=line.lower()
                if 4<=len(line)<=180 and any(k in low for k in ["answer","atsakymas","ats:","raktas","key","secret","slapta","slaptažodis","password","pass","code","kodas","token"]):
                    vf_add_answer(cands,line,"artifact_context:"+a.get("kind",""),"answer-like artifact line",int(a.get("score",0)//5)+25)
                    m=re.search(r"(?:answer|atsakymas|ats|raktas|key|secret|slapta|slaptažodis|password|pass|code|kodas|token)\s*[:=]\s*(.+)$",line,re.I)
                    if m: vf_add_answer(cands,m.group(1).strip(),"artifact_value:"+a.get("kind",""),"value after separator",int(a.get("score",0)//5)+60)
        except Exception:
            continue
    out=[]; seen=set()
    for x in sorted(cands,key=lambda z:z.get("score",0),reverse=True):
        k=x["value"].lower()
        if k not in seen:
            seen.add(k); out.append(x)
    return out[:120]
