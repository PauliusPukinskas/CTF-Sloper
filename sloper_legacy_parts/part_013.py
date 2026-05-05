# Auto-split from sloper_legacy_monolith.py lines 11431-...
def sf_tail_embedded_agent(report, root, data):
    data=bytes(data or b"")
    arts=[]
    # Only use PNG marker for actual PNG and JPG marker for actual JPG to avoid false tails.
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        marker=b"IEND\xaeB`\x82"; idx=data.find(marker)
        if idx>=0:
            tail=data[idx+len(marker):]
            if len(tail)>=8:
                art=sf_art(root,report,"png_iend_tail.bin",tail,"sprintforge_tail_data",170,"Data appended after PNG IEND marker.")
                if art: arts.append(art)
                arts += sf_embedded_compression_agent(report,root,tail)
    if data.startswith(b"\xff\xd8"):
        marker=b"\xff\xd9"; idx=data.rfind(marker)
        if idx>=0:
            tail=data[idx+len(marker):]
            if len(tail)>=8:
                art=sf_art(root,report,"jpeg_eoi_tail.bin",tail,"sprintforge_tail_data",170,"Data appended after JPEG EOI marker.")
                if art: arts.append(art)
                arts += sf_embedded_compression_agent(report,root,tail)
    arts += sf_embedded_compression_agent(report,root,data)
    return arts
def sl_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sf_trace(report, "SLOPER:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER:"+str(stage),
            "detail":str(detail)[:1000],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl_art(root, report, name, content, kind="sloper_artifact", score=120, note=""):
    outdir=root/"generated"/"sloper"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl_promote_text(report, text, source, why="", artifact=None, score=260):
    found=sf_promote_from_text(report,text,source,why,artifact,score) if "sf_promote_from_text" in globals() else 0
    # Promote compact answer body if statement expects ctf_cs and text is a single logical answer.
    line=str(text or "").strip()
    if "\n" not in line and sf_is_compact_answer_text(line) and not line.lower().startswith("ctf_cs{"):
        sf_add_body_candidate(report,line,source,why or "compact decoded answer",score+25,True,artifact)
        found+=1
    return found
def sl_zip_local_entries(data, max_entries=200):
    """Parse ZIP local file headers from arbitrary raw bytes.
    This works even when central directory offsets are wrong because the ZIP is carved from a disk image.
    """
    import struct as _struct, zlib as _zlib, bz2 as _bz2, lzma as _lzma
    data=bytes(data or b"")
    entries=[]
    positions=[m.start() for m in re.finditer(b"PK\x03\x04", data)]
    for start in positions[:max_entries]:
        try:
            if start+30>len(data): continue
            sig,ver,flag,comp,mt,md,crc,cs,us,nl,el=_struct.unpack_from("<IHHHHHIIIHH",data,start)
            if sig!=0x04034b50 or nl<=0 or nl>4096 or el>65535:
                continue
            name_b=data[start+30:start+30+nl]
            name=name_b.decode("utf-8","ignore") or f"entry_{start}"
            content_start=start+30+nl+el
            if content_start>=len(data): continue
            if cs and content_start+cs<=len(data):
                raw=data[content_start:content_start+cs]
                next_pos=content_start+cs
            else:
                nxts=[x for x in positions if x>content_start]
                cd=data.find(b"PK\x01\x02",content_start)
                eocd=data.find(b"PK\x05\x06",content_start)
                stops=nxts+([cd] if cd!=-1 else [])+([eocd] if eocd!=-1 else [])
                stop=min(stops) if stops else min(len(data),content_start+4_000_000)
                raw=data[content_start:stop]
                next_pos=stop
            dec=b""
            ok=False
            try:
                if comp==0:
                    dec=raw; ok=True
                elif comp==8:
                    dec=_zlib.decompress(raw,-15); ok=True
                elif comp==12:
                    dec=_bz2.decompress(raw); ok=True
                elif comp==14:
                    dec=_lzma.decompress(raw); ok=True
            except Exception:
                # Try incremental deflate when size was guessed.
                if comp==8:
                    try:
                        obj=_zlib.decompressobj(-15)
                        dec=obj.decompress(raw)
                        if dec:
                            ok=True
                    except Exception:
                        pass
            if ok:
                entries.append({"name":name,"offset":start,"compress_type":comp,"flag":flag,"compressed_size":len(raw),"declared_compressed_size":cs,"declared_size":us,"data":dec})
        except Exception:
            continue
    # Deduplicate by name/sha.
    out=[]; seen=set()
    import hashlib as _hashlib
    for e in entries:
        k=(e["name"],_hashlib.sha256(e["data"]).hexdigest()[:16])
        if k not in seen:
            seen.add(k); out.append(e)
    return out[:max_entries]
def sl_docx_local_header_carver(report, root, data):
    entries=sl_zip_local_entries(data, max_entries=300)
    if not entries:
        return []
    names=[e["name"] for e in entries]
    if not (any(n=="[Content_Types].xml" for n in names) or any(n.startswith("word/") for n in names)):
        return []
    outdir=root/"generated"/"sloper"/safe(report.get("name","file"))/"carved_ooxml_local_headers"
    outdir.mkdir(parents=True, exist_ok=True)
    arts=[]
    text_parts=[]
    manifest=[]
    for e in entries:
        name=e["name"]
        raw=e["data"]
        manifest.append({k:v for k,v in e.items() if k!="data"})
        out=outdir/safe(name)
        out.parent.mkdir(parents=True,exist_ok=True)
        try:
            out.write_bytes(raw)
            art={"kind":"sloper_carved_zip_entry","name":out.name,"path":str(out),"url":"/api/raw?path="+str(out),"source":"CTF SLOPER","score":210,"note":f"Local ZIP header carved entry: {name} @ {e.get('offset')}","exists":True,"size":out.stat().st_size,"file":report.get("rel","")}
            report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art)
        except Exception:
            pass
        if name.endswith(".xml"):
            xml=raw.decode("utf-8","ignore")
            txt=re.sub(r"<[^>]+>"," ",xml)
            txt=re.sub(r"\s+"," ",txt).strip()
            if txt:
                text_parts.append(f"--- {name} ---\n{txt}")
    full_text="\n".join(text_parts)
    mart=sl_art(root,report,"carved_ooxml_manifest.json",json.dumps(manifest,indent=2,ensure_ascii=False),"sloper_carved_ooxml_manifest",230,"OOXML/DOCX carved using local ZIP headers.")
    if mart: arts.append(mart)
    if full_text:
        tart=sl_art(root,report,"carved_ooxml_text.txt",full_text,"sloper_carved_ooxml_text",280,"Text extracted from carved OOXML XML files.")
        if tart: arts.append(tart)
        sl_promote_text(report,full_text,"SLOPER OOXML Carver","text from carved DOCX/OOXML",tart.get("path") if tart else "",290)
        # Look for strong compact custom-property style values.
        for m in re.finditer(r"\b([A-Za-z0-9]+(?:[_\-][A-Za-z0-9]+){2,})\b", full_text):
            val=m.group(1)
            if sf_is_compact_answer_text(val) or re.search(r"[a-z0-9]+_[a-z0-9]+_[a-z0-9]+",val.lower()):
                sf_add_body_candidate(report,val,"SLOPER OOXML Carver","compact value from OOXML metadata/body",285,True,tart.get("path") if tart else "")
    sl_trace(report,"OOXMLLocalCarver",f"{len(entries)} local ZIP entries, {len(text_parts)} XML text sections",280,mart.get("path") if mart else "")
    return arts
def sl_artifact_log_reconstruction_agent(report, root, data):
    text=data.decode("utf-8","ignore")
    if '"x"' not in text or '"rows"' not in text:
        return []
    entries=[]
    for line in text.splitlines():
        line=line.strip()
        if not line: continue
        try:
            obj=json.loads(line)
            if all(k in obj for k in ["x","y","rows"]) and isinstance(obj.get("rows"),list):
                entries.append(obj)
        except Exception:
            pass
    if len(entries)<3:
        return []
    allowed=set(" $/_\\|")
    scored=[]
    for e in entries:
        raw="".join(e.get("rows",[]))
        if not raw: continue
        ratio=sum(ch in allowed for ch in raw)/max(1,len(raw))
        # keep ASCII-art looking chunks; drop randomized noise chunks.
        if ratio>=0.70:
            scored.append(e)
    if not scored:
        return []
    maxx=max(int(e["x"])+max(len(r) for r in e["rows"]) for e in scored)
    maxy=max(int(e["y"])+len(e["rows"]) for e in scored)
    canvas=[[" "]*maxx for _ in range(maxy)]
    for e in scored:
        x=int(e["x"]); y=int(e["y"])
        for dy,row in enumerate(e["rows"]):
            for dx,ch in enumerate(row):
                if ch!=" ":
                    yy=y+dy; xx=x+dx
                    if 0<=yy<maxy and 0<=xx<maxx:
                        canvas[yy][xx]=ch
    art_text="\n".join("".join(r).rstrip() for r in canvas)
    art=sl_art(root,report,"artifact_log_reconstructed_ascii.txt",art_text,"sloper_artifact_log_reconstruction",260,f"Reconstructed {len(scored)}/{len(entries)} coordinate chunks into ASCII canvas.")
    # Create compact metadata report.
    meta={"entries_total":len(entries),"entries_used":len(scored),"width":maxx,"height":maxy,"note":"Noise chunks filtered by ASCII-art character ratio."}
    mart=sl_art(root,report,"artifact_log_reconstruction_meta.json",json.dumps(meta,indent=2,ensure_ascii=False),"sloper_artifact_log_meta",180,"Artifact reconstruction metadata.")
    sl_trace(report,"ArtifactLogReconstruction",f"canvas {maxx}x{maxy}; used {len(scored)} chunks",260,art.get("path") if art else "")
    return [x for x in [art,mart] if x]
def sl_time_anomaly_agent(report, root, data):
    import datetime as _dt
    text=data.decode("utf-8","ignore")
    if "Time drift" not in text and "Time anomaly" not in text and not re.search(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",text):
        return []
    rows=[]
    for line in text.splitlines():
        m=re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:(\d\d)Z)\s+(\S+)\s+(\S+)\s+(.*)",line)
        if m:
            try:
                dt=_dt.datetime.fromisoformat(m.group(1).replace("Z","+00:00"))
                rows.append({"dt":dt,"line":line,"sec":dt.second,"minute":dt.minute,"module":m.group(3),"level":m.group(4),"msg":m.group(5)})
            except Exception:
                pass
    if len(rows)<5:
        return []
    anomalies=[]
    prev=None
    deltas=[]
    for r in rows:
        if prev:
            d=int((r["dt"]-prev["dt"]).total_seconds())
            deltas.append(d)
            if d<=0 or "anomaly" in r["msg"].lower() or "drift" in r["msg"].lower():
                rr=dict(r); rr["delta_from_prev"]=d; anomalies.append(rr)
        prev=r
    drift=[r for r in rows if "drift" in r["msg"].lower() or "anomaly" in r["msg"].lower()]
    variants={}
    for label,arr in [
        ("anomaly_seconds",[r["sec"] for r in anomalies]),
        ("drift_seconds",[r["sec"] for r in drift]),
        ("delta_values_mod256",[d&255 for d in deltas]),
        ("negative_delta_positions",[i for i,d in enumerate(deltas) if d<=0]),
    ]:
        if arr:
            variants[label+"_ascii"]="".join(chr(x) if 32<=x<127 else "." for x in arr[:2000])
            variants[label+"_numbers"]=" ".join(map(str,arr[:2000]))
    obj={"rows":len(rows),"anomalies":len(anomalies),"drift_or_anomaly_lines":len(drift),"variants":variants,"sample_anomalies":[{k:(v.isoformat() if hasattr(v,'isoformat') else v) for k,v in a.items()} for a in anomalies[:30]]}
    art=sl_art(root,report,"time_anomaly_candidates.json",json.dumps(obj,indent=2,ensure_ascii=False),"sloper_time_anomaly_candidates",210,"Timestamp drift/anomaly sequences and ASCII candidates.")
    for v in variants.values():
        sl_promote_text(report,v,"SLOPER TimeAnomaly","timestamp anomaly derived sequence",art.get("path") if art else "",180)
    sl_trace(report,"TimeAnomalyAgent",f"{len(anomalies)} anomalies, {len(drift)} drift/anomaly lines",210,art.get("path") if art else "")
    return [art] if art else []
def sl_pcap_scalar_agent(report, root, data):
    p=Path(report.get("path",""))
    if p.suffix.lower() not in [".pcap",".pcapng"] and report.get("kind")!="pcap":
        return []
    if not exists("tshark"):
        return []
    arts=[]
    fields=[
        ("ip_id",["tshark","-r",str(p),"-T","fields","-e","ip.id"]),
        ("ip_ttl",["tshark","-r",str(p),"-T","fields","-e","ip.ttl"]),
        ("ip_len",["tshark","-r",str(p),"-T","fields","-e","ip.len"]),
        ("tcp_window",["tshark","-r",str(p),"-T","fields","-e","tcp.window_size_value"]),
        ("tcp_payload",["tshark","-r",str(p),"-Y","tcp.len>0","-T","fields","-e","tcp.payload"]),
        ("udp_payload",["tshark","-r",str(p),"-Y","udp.length>8","-T","fields","-e","data.data"]),
        ("icmp_data",["tshark","-r",str(p),"-Y","icmp","-T","fields","-e","data.data"]),
        ("dns_names",["tshark","-r",str(p),"-Y","dns","-T","fields","-e","dns.qry.name","-e","dns.txt"]),
        ("http",["tshark","-r",str(p),"-Y","http","-T","fields","-e","http.host","-e","http.request.uri","-e","http.cookie","-e","http.file_data"]),
    ]
    summary={}
    for name,cmd in fields:
        try:
            r=run(cmd,20)
            out=r.get("out","")[:600000]
            if not out.strip(): continue
            report.setdefault("outputs",[]).append({"tool":"sloper_pcap_"+name,"ok":r.get("ok"),"cmd":r.get("cmd"),"out":out[:60000]})
            art=sl_art(root,report,f"pcap_{name}.txt",out,"sloper_pcap_field",165,f"tshark extraction: {name}")
            if art: arts.append(art)
            summary[name]=out[:20000]
            # Numeric fields: bytes, low bytes, deltas.
            nums=[]
            for tok in re.findall(r"0x[0-9a-fA-F]+|\b\d+\b",out):
                try: nums.append(int(tok,0))
                except Exception: pass
            if nums:
                variants={
                    name+"_low8":"".join(chr(n&255) if 32<=n&255<127 else "." for n in nums[:4000]),
                    name+"_delta_low8":"".join(chr((nums[i]-nums[i-1])&255) if 32<=((nums[i]-nums[i-1])&255)<127 else "." for i in range(1,min(len(nums),4000))),
                }
                vart=sl_art(root,report,f"pcap_{name}_scalar_variants.json",json.dumps({"count":len(nums),"variants":variants},indent=2),"sloper_pcap_scalar_variants",190,f"Scalar low-byte/delta candidates for {name}.")
                if vart: arts.append(vart)
                for txt in variants.values():
                    sl_promote_text(report,txt,"SLOPER PCAP Scalar",f"{name} low-byte/delta sequence",vart.get("path") if vart else "",200)
            # Hex payload fields.
            if name in ["tcp_payload","udp_payload","icmp_data"]:
                joined=""
                for line in out.splitlines()[:3000]:
                    hx=re.sub(r"[^0-9a-fA-F]","",line)
                    if len(hx)>=2 and len(hx)%2==0:
                        try: joined+=bytes.fromhex(hx).decode("utf-8","ignore")+"\n"
                        except Exception: pass
                if joined.strip():
                    hart=sl_art(root,report,f"pcap_{name}_hex_ascii.txt",joined,"sloper_pcap_payload_ascii",230,f"Decoded hex payload bytes from {name}.")
                    if hart: arts.append(hart)
                    sl_promote_text(report,joined,"SLOPER PCAP Payload",f"{name} decoded hex payload",hart.get("path") if hart else "",250)
            else:
                sl_promote_text(report,out,"SLOPER PCAP Field",name,art.get("path") if art else "",180)
        except Exception:
            pass
    if arts:
        sl_trace(report,"PCAPScalarAgent",f"{len(arts)} PCAP extraction artifacts",220,arts[0].get("path"))
    return arts
def sl_pyc_constants_agent(report, root, data):
    p=Path(report.get("path",""))
    if p.suffix.lower()!=".pyc":
        return []
    import marshal as _marshal, types as _types, base64 as _base64, binascii as _binascii
    arts=[]
    constants=[]
    code=None
    for hdr in [16,12]:
        try:
            code=_marshal.loads(data[hdr:])
            break
        except Exception:
            pass
    if not code:
        return []
    def rec(c):
        for x in c.co_consts:
            if isinstance(x,_types.CodeType):
                rec(x)
            else:
                if isinstance(x,(str,bytes,int,float)):
                    constants.append(x)
    try: rec(code)
    except Exception: pass
    decoded=[]
    for c in constants:
        if isinstance(c,bytes):
            s=c.decode("utf-8","ignore")
        else:
            s=str(c)
        if not s or len(s)>500: continue
        item={"value":s}
        # base64
        if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}",s) and len(s)%4 in [0,2,3]:
            try:
                pad=s+"="*((4-len(s)%4)%4)
                raw=_base64.urlsafe_b64decode(pad.encode())
                dec=raw.decode("utf-8","ignore")
                if dec:
                    item["base64_decoded"]=dec
                    decoded.append(dec)
            except Exception:
                pass
        decoded.append(s)
    cwe=[]
    joined="\n".join(decoded)
    for m in re.finditer(r"\bCWE[-_ ]?(\d{2,4})\b",joined,re.I):
        cwe.append("CWE-"+m.group(1))
    # heuristic CWE suggestions for common backdoor/auth constants
    low=joined.lower()
    if any(k in low for k in ["sk_live","secret","jwt","hs256","csrf_token","recovery","token"]):
        cwe += ["CWE-798", "CWE-321"]
    if any(k in low for k in ["admin","administrator","password_hash","qwerty"]):
        cwe += ["CWE-798"]
    # strong phrase candidates from decoded base64 and constants
    phrases=[]
    for s in decoded:
        st=s.strip()
        if 4<=len(st)<=80 and re.fullmatch(r"[A-Za-z0-9_\-+.]+",st) and ("_" in st or any(ch.isdigit() for ch in st)):
            if not re.fullmatch(r"[a-fA-F0-9]{24,}",st):
                phrases.append(st)
    obj={"constants_count":len(constants),"constants":[str(x)[:300] for x in constants[:500]],"decoded_values":decoded[:500],"cwe_suggestions":list(dict.fromkeys(cwe)),"phrase_candidates":list(dict.fromkeys(phrases))}
    art=sl_art(root,report,"pyc_constants_decoded.json",json.dumps(obj,indent=2,ensure_ascii=False),"sloper_pyc_constants",260,"PYC constants with base64/JWT/secret/CWE analysis.")
    if art: arts.append(art)
    for ph in obj["phrase_candidates"][:20]:
        for code in obj["cwe_suggestions"][:8] or [""]:
            body=f"{ph}+{code}" if code else ph
            sf_add_body_candidate(report,body,"SLOPER PYC Constants","phrase/CWE candidate from pyc constants",260,False,art.get("path") if art else "")
    sl_promote_text(report,joined,"SLOPER PYC Constants","decoded constants",art.get("path") if art else "",210)
    sl_trace(report,"PYCConstantsAgent",f"{len(constants)} constants, {len(obj['phrase_candidates'])} phrase candidates, {len(obj['cwe_suggestions'])} CWE suggestions",260,art.get("path") if art else "")
    return arts
def sl_run_agents(report, root, data):
    p=Path(report.get("path",""))
    text=data[:800000].decode("utf-8","ignore")
    arts=[]
    # universal direct compact extraction
    try: sl_promote_text(report,text+"\n"+"\n".join(report.get("strings",[])[:1000]),"SLOPER DirectScan","direct scan",None,250)
    except Exception: pass
    # robust carving
    try: arts += sl_docx_local_header_carver(report,root,data)
    except Exception as e: sl_trace(report,"OOXMLLocalCarver failed",str(e),0)
    # challenge-specific general agents by structure/type
    try: arts += sl_artifact_log_reconstruction_agent(report,root,data)
    except Exception as e: sl_trace(report,"ArtifactLogReconstruction failed",str(e),0)
    try: arts += sl_time_anomaly_agent(report,root,data)
    except Exception as e: sl_trace(report,"TimeAnomaly failed",str(e),0)
    try: arts += sl_pcap_scalar_agent(report,root,data)
    except Exception as e: sl_trace(report,"PCAPScalar failed",str(e),0)
    try: arts += sl_pyc_constants_agent(report,root,data)
    except Exception as e: sl_trace(report,"PYCConstants failed",str(e),0)
    # better text transposition trigger
    hints=(ux_statement_text(report)+" "+p.name+" "+text[:1000]).lower()
    if any(k in hints for k in ["transpoz", "teisinga tvarka", "išdėstyti", "isdestyti", "raktas", "[key]", "route", "matrix", "matrica"]):
        try: arts += sf_transposition_agent(report,root,text)
        except Exception as e: sl_trace(report,"Transposition failed",str(e),0)
    # final refresh
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: pass
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    return arts
_prev_sf_route_file_agents_v41 = sf_route_file_agents
def sf_route_file_agents(report, root, data):
    # Existing v40 routes first, then v41 agents for missing classes.
    try:
        _prev_sf_route_file_agents_v41(report,root,data)
    except Exception as e:
        sl_trace(report,"previous route failed",str(e),0)
    try:
        sl_run_agents(report,root,data)
    except Exception as e:
        sl_trace(report,"SLOPER agents failed",str(e),0)
    # final promotion: keep evidence-backed flags only
    promoted=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        if wf_flag_has_solve_evidence(report,f):
            promoted.append(f)
    report["flags"]=promoted[:30]
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: pass
    return report.get("artifacts",[])
_prev_vf_postprocess_v41 = vf_postprocess
def vf_postprocess(report, root):
    report=_prev_vf_postprocess_v41(report, root)
    try:
        data=Path(report.get("path","")).read_bytes()[:120_000_000]
        sl_run_agents(report,root,data)
    except Exception as e:
        sl_trace(report,"postprocess agents failed",str(e),0)
    promoted=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        if wf_flag_has_solve_evidence(report,f):
            promoted.append(f)
    report["flags"]=promoted[:30]
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: pass
    try: af_evidence_score_candidates(report)
    except Exception: pass
    return report
_prev_project_summary_v41 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v41(reports, meta)
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper" in txt: s+=1200
        if any(k in txt for k in ["ooxml","docx","artifact_log","time_anomaly","pcap","pyc","carved","constants"]): s+=350
        if "sprintforge" in txt: s+=500
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(summary.get("artifacts",[]),key=pri,reverse=True)[:2000]
    summary["sloper_status"]={
        "flags":len(summary.get("flags",[])),
        "answers":len(summary.get("answer_candidates",[])),
        "wrappers":len(summary.get("flag_wrapping_helpers",[])),
        "artifacts":len(summary.get("artifacts",[])),
        "note":"Use Solve Trace first, then Artifacts, then Wrappers if no promoted flag exists."
    }
    return summary
APP_TITLE = "CTF SLOPER v41"
def sl_flag_has_evidence(report, flag):
    flag=ux_canonical_flag(flag)
    if not smartsolve_strict_target_flag_ok(flag):
        return False
    low=flag.lower()
    # Existing global evidence logic first.
    try:
        if wf_flag_has_solve_evidence(report, flag):
            return True
    except Exception:
        pass
    # SLOPER/SprintForge artifacts and traces are direct evidence if they mention the flag
    # or mention the decoded body inside the flag.
    body=flag_inner(flag).lower()
    trace_text=" ".join(str(x) for x in report.get("solve_trace",[])+report.get("agent_trace",[])).lower()
    if low in trace_text or body in trace_text:
        return True
    for a in report.get("artifacts",[])[:500]:
        p=Path(a.get("path",""))
        kind=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("note",""))).lower()
        if any(src in kind for src in ["sloper","sprintforge","reverseforge"]):
            try:
                if p.exists() and p.is_file() and p.stat().st_size<2_000_000:
                    txt=p.read_bytes()[:400000].decode("utf-8","ignore").lower()
                    if low in txt or body in txt:
                        return True
            except Exception:
                pass
    for ans in report.get("answer_candidates",[])[:200]:
        val=str(ans.get("value","")).lower()
        src=str(ans.get("source","")).lower()
        if (val==low or val==body or body in val) and any(s in src for s in ["sloper","sprintforge","reverseforge","promoted flag"]):
            return True
    return False
def sl_finalize_report(report):
    promoted=[]
    for f in list(dict.fromkeys([ux_canonical_flag(x) for x in report.get("flags",[]) if smartsolve_strict_target_flag_ok(x)])):
        if sl_flag_has_evidence(report,f):
            promoted.append(f)
    report["flags"]=promoted[:30]
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: pass
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    return report
_prev_sf_route_file_agents_v41_evidence = sf_route_file_agents
def sf_route_file_agents(report, root, data):
    try:
        _prev_sf_route_file_agents_v41_evidence(report, root, data)
    except Exception as e:
        sl_trace(report,"route failed",str(e),0)
    return sl_finalize_report(report).get("artifacts",[])
_prev_vf_postprocess_v41_evidence = vf_postprocess
def vf_postprocess(report, root):
    report=_prev_vf_postprocess_v41_evidence(report, root)
    return sl_finalize_report(report)
def sl_collect_candidate_flags(report):
    cands=[]
    for f in report.get("flags",[])[:200]:
        if smartsolve_strict_target_flag_ok(f):
            cands.append(ux_canonical_flag(f))
    for t in report.get("solve_trace",[])+report.get("agent_trace",[]):
        f=t.get("flag") if isinstance(t,dict) else None
        if f and smartsolve_strict_target_flag_ok(f):
            cands.append(ux_canonical_flag(f))
        txt=str(t)
        for ff in vf_primary_flags(txt,limit=10,scan_limit=5000):
            cands.append(ux_canonical_flag(ff))
    for a in report.get("answer_candidates",[])[:300]:
        v=str(a.get("value",""))
        if smartsolve_strict_target_flag_ok(v):
            cands.append(ux_canonical_flag(v))
    for w in report.get("flag_wrapping_helpers",[])[:200]:
        v=str(w.get("suggested_flag",""))
        if smartsolve_strict_target_flag_ok(v):
            cands.append(ux_canonical_flag(v))
    # Read small text artifacts for strict ctf_cs.
    for art in report.get("artifacts",[])[:300]:
        p=Path(art.get("path",""))
        try:
            if p.exists() and p.is_file() and p.stat().st_size<1_500_000:
                txt=p.read_bytes()[:300000].decode("utf-8","ignore")
                for ff in vf_primary_flags(txt,limit=20,scan_limit=300000):
                    cands.append(ux_canonical_flag(ff))
                # compact answer body from decoded SLOPER/SprintForge text artifact
                if any(s in (str(art.get("source",""))+" "+str(art.get("kind",""))).lower() for s in ["sloper","sprintforge","reverseforge"]):
                    line=txt.strip()
                    if sf_is_compact_answer_text(line):
                        clean_line = re.sub(r'[^A-Za-z0-9_\\-:.+]', '', line)
                        cand = f"ctf_cs{{{clean_line}}}"
                        if smartsolve_strict_target_flag_ok(cand):
                            cands.append(ux_canonical_flag(cand))
        except Exception:
            pass
    out=[]; seen=set()
    for f in cands:
        k=f.lower()
        if k not in seen:
            seen.add(k); out.append(f)
    return out
def sl_finalize_report(report):
    candidate_flags=sl_collect_candidate_flags(report)
    promoted=[]
    # Temporarily add candidates so sl_flag_has_evidence can inspect answer/trace/artifact support.
    old_flags=list(report.get("flags",[]))
    report["flags"]=list(dict.fromkeys(old_flags+candidate_flags))
    for f in candidate_flags:
        if sl_flag_has_evidence(report,f):
            promoted.append(f)
    report["flags"]=promoted[:30]
    report["answer_candidates"]=vf_collect_answer_candidates(report)
    try: report["flag_wrapping_helpers"]=ff_candidate_to_flag_helpers(report)
    except Exception: pass
    try: af_evidence_score_candidates(report)
    except Exception: pass
    try: report["autopilot_review"]=ff_autopilot_review(report)
    except Exception: pass
    return report
def sf_route_file_agents(report, root, data):
    try:
        _prev_sf_route_file_agents_v41_evidence(report, root, data)
    except Exception as e:
        sl_trace(report,"route failed",str(e),0)
    return sl_finalize_report(report).get("artifacts",[])
def vf_postprocess(report, root):
    report=_prev_vf_postprocess_v41_evidence(report, root)
    return sl_finalize_report(report)
def sl42_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl_trace(report, "v42:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v42:"+str(stage),
            "detail":str(detail)[:1000],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl42_art(root, report, name, content, kind="sloper42_artifact", score=130, note=""):
    outdir=root/"generated"/"sloper42"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v42","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl42_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl42_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
MORSE = {
    ".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",
    ".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R",
    "...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z",
    "-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"
}
def sl42_decode_morse(s):
    s=str(s or "").strip()
    if not re.fullmatch(r"[.\-/\s]+",s) or "." not in s or "-" not in s:
        return ""
    words=[]
    for word in re.split(r"\s*/\s*|\s{3,}",s):
        chars=[]
        for tok in word.strip().split():
            if tok in MORSE:
                chars.append(MORSE[tok])
        if chars:
            words.append("".join(chars))
    return " ".join(words)
def sl42_safe_b64_decode(s):
    import base64
    out=[]
    s=str(s or "").strip()
    for token in re.findall(r"[A-Za-z0-9+/=_-]{8,}",s):
        if len(token)>1000: continue
        for mode in ["std","urlsafe"]:
            try:
                pad=token+"="*((4-len(token)%4)%4)
                raw=(base64.b64decode if mode=="std" else base64.urlsafe_b64decode)(pad.encode())
                txt=raw.decode("utf-8","ignore")
                if txt and sum(32<=ord(c)<127 or c in "\n\r\t" for c in txt)/max(1,len(txt))>0.75:
                    out.append(txt)
            except Exception:
                pass
    return out
def sl42_decode_chain_text(text, max_rounds=3):
    """Small robust decode chain for clues/passwords/answers."""
    seen=set()
    queue=[str(text or "")]
    results=[]
    for depth in range(max_rounds):
        nxt=[]
        for s in queue:
            if not s or s in seen: continue
            seen.add(s); results.append((depth,"raw",s))
            # Morse
            mor=sl42_decode_morse(s)
            if mor and mor not in seen:
                nxt.append(mor); results.append((depth+1,"morse",mor))
            # base64/url base64
            for b in sl42_safe_b64_decode(s):
                if b not in seen:
                    nxt.append(b); results.append((depth+1,"base64",b))
            # hex
            for hx in re.findall(r"(?:[0-9a-fA-F]{2}){4,}",s):
                if len(hx)>4000: continue
                try:
                    dec=bytes.fromhex(hx).decode("utf-8","ignore")
                    if dec and dec not in seen:
                        nxt.append(dec); results.append((depth+1,"hex",dec))
                except Exception:
                    pass
            # URL percent
            if "%" in s:
                try:
                    from urllib.parse import unquote
                    dec=unquote(s)
                    if dec!=s and dec not in seen:
                        nxt.append(dec); results.append((depth+1,"url_percent",dec))
                except Exception:
                    pass
            # ROT13
            try:
                import codecs
                dec=codecs.decode(s,"rot_13")
                if dec!=s and dec not in seen and any(w in dec.lower() for w in ["ctf","flag","secret","password","slapta","raktas"]):
                    nxt.append(dec); results.append((depth+1,"rot13",dec))
            except Exception:
                pass
        queue=nxt[:200]
    # Dedup by text
    out=[]; seen2=set()
    for d,m,s in results:
        k=s.strip()
        if k and k not in seen2:
            seen2.add(k); out.append({"depth":d,"method":m,"text":k})
    return out[:500]
def sl42_extract_clue_values(text):
    """Extract possible passwords, keys, codes and compact answer bodies from text."""
    vals=[]
    text=str(text or "")
    # explicit labels
    label_re=r"(?:password|pass|pwd|key|raktas|slaptažodis|slaptazodis|secret|token|code|kodas|comment|komentaras)\s*[:=]\s*['\"]?([A-Za-z0-9_\-+.@:/=]{3,160})"
    for m in re.finditer(label_re,text,re.I):
        vals.append({"value":m.group(1).strip("'\""),"source":"label","score":180})
    # ctf body / braces
    for m in re.finditer(r"\{([A-Za-z0-9_\-:.+]{4,160})\}",text):
        vals.append({"value":m.group(1),"source":"braced_body","score":210})
    # morse lines
    for line in text.splitlines():
        if re.fullmatch(r"[.\-/\s]{8,}",line.strip()) and "." in line and "-" in line:
            dec=sl42_decode_morse(line)
            if dec:
                vals.append({"value":dec.strip().replace(" ","_"),"source":"morse","score":190})
    # compact high-value tokens
    for tok in re.findall(r"\b[A-Za-z0-9][A-Za-z0-9_\-+.]{5,120}\b",text):
        low=tok.lower()
        if any(w in low for w in ["cyber","sprint","flag","secret","pass","key","slapta","raktas","morse","zip","stego","b4ck","d33t"]):
            vals.append({"value":tok,"source":"compact_token","score":150})
    # decode chain
    for r in sl42_decode_chain_text(text,2):
        t=r["text"]
        for v in sl42_extract_clue_values_nochain(t):
            v["source"]="chain_"+r["method"]+"_"+v["source"]
            v["score"]+=30
            vals.append(v)
    # normalized variants
    out=[]; seen=set()
    for v in vals:
        val=str(v.get("value","")).strip()
        if not val or len(val)>200: continue
        for vv in [val, val.lower(), val.replace(" ","_")]:
            vv=vv.strip()
            k=vv.lower()
            if 3<=len(vv)<=200 and k not in seen:
                seen.add(k); out.append({"value":vv,"source":v.get("source",""),"score":v.get("score",100)})
    return sorted(out,key=lambda x:x.get("score",0),reverse=True)[:300]
def sl42_extract_clue_values_nochain(text):
    vals=[]
    text=str(text or "")
    label_re=r"(?:password|pass|pwd|key|raktas|slaptažodis|slaptazodis|secret|token|code|kodas|comment|komentaras)\s*[:=]\s*['\"]?([A-Za-z0-9_\-+.@:/=]{3,160})"
    for m in re.finditer(label_re,text,re.I):
        vals.append({"value":m.group(1).strip("'\""),"source":"label","score":180})
    for m in re.finditer(r"\{([A-Za-z0-9_\-:.+]{4,160})\}",text):
        vals.append({"value":m.group(1),"source":"braced_body","score":210})
    for line in text.splitlines():
        if re.fullmatch(r"[.\-/\s]{8,}",line.strip()) and "." in line and "-" in line:
            dec=sl42_decode_morse(line)
            if dec:
                vals.append({"value":dec.strip().replace(" ","_"),"source":"morse","score":190})
    return vals
def sl42_report_text_blob(report, max_bytes=300000):
    parts=[]
    parts += report.get("strings",[])[:1000]
    for o in report.get("outputs",[])[:80]:
        parts.append((o.get("out") or "")[:20000])
    for c in report.get("chain_results",[])[:100]:
        parts.append((c.get("output") or "")[:20000])
    for a in report.get("artifacts",[])[:200]:
        p=Path(a.get("path",""))
        try:
            if p.exists() and p.is_file() and p.stat().st_size<max_bytes:
                parts.append(p.read_bytes()[:max_bytes].decode("utf-8","ignore"))
        except Exception:
            pass
    return "\n".join(str(x) for x in parts if x)
def sl42_try_extract_archive_with_passwords(report, root, archive_path, passwords, label="archive"):
    arts=[]
    p=Path(archive_path)
    if not p.exists(): return []
    outbase=root/"generated"/"sloper42"/safe(report.get("name","file"))/"password_extract"
    outbase.mkdir(parents=True, exist_ok=True)
    pwlist=[]
    for x in passwords:
        v=str(x.get("value",x) if isinstance(x,dict) else x).strip()
        if v and v not in pwlist and len(v)<=160:
            pwlist.append(v)
    pwlist=[""]+pwlist+["password","secret","slapta","raktas","ctf","cyber","sprint"]
    pwlist=list(dict.fromkeys(pwlist))[:80]
    for pw in pwlist:
        try:
            outdir=outbase/(safe(p.stem)+"_"+safe(pw or "empty"))
            outdir.mkdir(parents=True, exist_ok=True)
            ok=False; output=""
            if exists("7z"):
                r=run(["7z","x","-y",f"-p{pw}",f"-o{outdir}",str(p)],20)
                output=r.get("out","")
                ok=r.get("ok") and any(q.is_file() for q in outdir.rglob("*"))
            elif p.suffix.lower()==".zip":
                import zipfile as _zipfile
                with _zipfile.ZipFile(p) as z:
                    for n in z.namelist():
                        try:
                            raw=z.read(n,pwd=(pw.encode() if pw else None))
                            out=(outdir/safe(n))
                            out.parent.mkdir(parents=True,exist_ok=True)
                            out.write_bytes(raw)
                            ok=True
                        except Exception:
                            pass
            if ok:
                art=sl42_art(root,report,f"{safe(label)}_extract_password_{safe(pw or 'empty')}.txt",output,"sloper42_password_extract",260,f"Extracted {p.name} using password candidate {pw!r}.")
                if art: arts.append(art)
                # Add extracted children as artifacts and scan them
                for child in outdir.rglob("*"):
                    if child.is_file():
                        cart={"kind":"sloper42_extracted_child","name":child.name,"path":str(child),"url":"/api/raw?path="+str(child),"source":"CTF SLOPER v42","score":240,"note":f"Child extracted from {p.name} with password {pw!r}.","exists":True,"size":child.stat().st_size,"file":report.get("rel","")}
                        report.setdefault("artifacts",[]).append(cart); report.setdefault("transformations",[]).append(cart); arts.append(cart)
                        try:
                            raw=child.read_bytes()
                            txt=raw[:300000].decode("utf-8","ignore")
                            sl_promote_text(report,txt,"SLOPER v42 ArchivePassword",f"extracted child {child.name}",str(child),280)
                            sf_embedded_compression_agent(report,root,raw)
                        except Exception:
                            pass
                sl42_trace(report,"PasswordArchive",f"{p.name} extracted with password {pw!r}",280,art.get("path") if art else "")
                break
        except Exception:
            pass
    return arts
