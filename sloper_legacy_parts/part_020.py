# Auto-split from sloper_legacy_monolith.py lines 17752-...
def project_summary(reports, meta):
    summary=_prev_project_summary_v53(reports, meta)
    artifacts=summary.get("artifacts",[]) or []
    lane=summary.get("sloper52_review_lanes",{}) or summary.get("sloper51_review_lanes",{}) or summary.get("sloper50_review_lanes",{}) or {}
    lane["v53_zip_passwords"]=len([a for a in artifacts if "sloper53_zip_password" in a.get("kind","") or "zip_password_manifest" in a.get("name","")])
    lane["v53_audio"]=len([a for a in artifacts if "wav_lsb" in a.get("name","") or "sloper53_wav" in a.get("kind","")])
    lane["v53_sqlite"]=len([a for a in artifacts if "sqlite_dump" in a.get("name","")])
    lane["v53_documents"]=len([a for a in artifacts if "document_raw_text" in a.get("name","")])
    lane["v53_source_deobf"]=len([a for a in artifacts if "source_deobf" in a.get("name","")])
    summary["sloper53_review_lanes"]=lane
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper53" in txt or "v53" in txt: s+=9000
        if any(k in txt for k in ["sqlite_dump","wav_lsb","source_deobf","document_raw_text","zip_password_manifest"]): s+=1600
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(artifacts,key=pri,reverse=True)[:5500]
    brief=summary.get("sloper52_project_brief",{}) or summary.get("sloper51_project_brief",{}) or summary.get("sloper50_project_brief",{}) or {}
    brief["v53_universal_coverage"]="active"
    if lane.get("v53_zip_passwords"): brief["inspect_first"]="zip_password_manifest.json"
    elif lane.get("v53_audio"): brief["inspect_first"]="wav_lsb_manifest.json"
    elif lane.get("v53_sqlite"): brief["inspect_first"]="sqlite_dump.json"
    elif lane.get("v53_documents"): brief["inspect_first"]="document_raw_text_extract.txt"
    elif lane.get("v53_source_deobf"): brief["inspect_first"]="source_deobf_candidates.json"
    summary["sloper53_project_brief"]=brief
    matrix={
        "archive_passwords":lane.get("v53_zip_passwords",0),
        "audio":lane.get("v53_audio",0),
        "database":lane.get("v53_sqlite",0),
        "documents":lane.get("v53_documents",0),
        "source_deobf":lane.get("v53_source_deobf",0),
        "magic_carving":lane.get("v52_magic_carves",0),
        "transformed_children":lane.get("v50_transformed_children",0),
        "pcap":lane.get("v51_pure_pcap",0) or lane.get("v48_pcap_artifacts",0),
        "image_stego":lane.get("v51_png_streams",0) or lane.get("v49_visual_artifacts",0),
    }
    summary["sloper53_coverage_matrix"]=matrix
    na=summary.get("sloper52_next_actions",[]) or summary.get("sloper51_next_actions",[]) or summary.get("workflow_steps",[]) or []
    if lane.get("v53_zip_passwords"):
        na.insert(0,{"priority":98,"step":"Open zip_password_manifest.json.","why":"v53 tried clue-derived passwords and extracted archive members."})
    if lane.get("v53_audio"):
        na.insert(0,{"priority":97,"step":"Open wav_lsb_manifest.json.","why":"v53 extracted audio LSB streams."})
    if lane.get("v53_sqlite"):
        na.insert(0,{"priority":96,"step":"Open sqlite_dump.json.","why":"v53 dumped database schema and rows."})
    if lane.get("v53_source_deobf"):
        na.insert(0,{"priority":95,"step":"Open source_deobf_candidates.json.","why":"v53 decoded literals and charcode/base64/hex source patterns."})
    summary["sloper53_next_actions"]=na[:42]
    summary["workflow_steps"]=na[:42]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v53"
def sl54_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl53_trace(report, "v54:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v54:"+str(stage),
            "detail":str(detail)[:1800],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl54_art(root, report, name, content, kind="sloper54_artifact", score=230, note=""):
    outdir=root/"generated"/"sloper54"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v54","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl54_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl54_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl54_promote_text(report, text, source, artifact=None, score=285):
    try:
        sl45_promote_answer_markers(report,text,source,artifact,score)
    except Exception:
        pass
    try:
        for f in vf_primary_flags(str(text),limit=10,scan_limit=400000):
            if f not in report.setdefault("flags",[]):
                report["flags"].append(f)
                sl54_trace(report,"strict flag",f,score,artifact,f)
    except Exception:
        pass
def sl54_entropy(buf):
    if not buf:
        return 0.0
    import math
    counts=[0]*256
    for b in buf:
        counts[b]+=1
    n=len(buf)
    ent=0.0
    for c in counts:
        if c:
            p=c/n
            ent-=p*math.log2(p)
    return ent
def sl54_entropy_map_agent(report, root, data):
    data=bytes(data or b"")
    if len(data)<2048 or len(data)>30_000_000:
        return []
    block=4096
    rows=[]
    for off in range(0,len(data),block):
        chunk=data[off:off+block]
        if len(chunk)<512:
            continue
        ent=sl54_entropy(chunk)
        printable=sum(1 for b in chunk if 32<=b<127 or b in (9,10,13))/len(chunk)
        rows.append({"offset":off,"hex":hex(off),"size":len(chunk),"entropy":round(ent,4),"printable_ratio":round(printable,4)})
    # mark interesting jumps
    interesting=[]
    for i,r in enumerate(rows):
        if r["entropy"]>=7.6 or r["printable_ratio"]>=0.85:
            interesting.append(r)
        elif 0<i<len(rows)-1:
            if abs(r["entropy"]-rows[i-1]["entropy"])>=1.2 or abs(r["entropy"]-rows[i+1]["entropy"])>=1.2:
                interesting.append(r)
    obj={"block_size":block,"file_size":len(data),"blocks":rows[:20000],"interesting_offsets":interesting[:1000]}
    art=sl54_art(root,report,"entropy_offset_map.json",json.dumps(obj,indent=2,ensure_ascii=False),"sloper54_entropy_offset_map",260,"Entropy/printable-ratio map for embedded, packed or text-heavy regions.")
    if art:
        report.setdefault("next_steps",[]).append({"priority":75,"step":"Review entropy_offset_map.json if no flag is found.","why":"High-entropy or printable regions may indicate compressed/encrypted/embedded payloads."})
        return [art]
    return []
def sl54_magic_signatures():
    return [
        ("zip", b"PK\x03\x04", ".zip", "ZIP/APK/DOCX/JAR"),
        ("gzip", b"\x1f\x8b\x08", ".gz", "Gzip"),
        ("bzip2", b"BZh", ".bz2", "BZip2"),
        ("xz", b"\xfd7zXZ\x00", ".xz", "XZ"),
        ("png", b"\x89PNG\r\n\x1a\n", ".png", "PNG"),
        ("jpg", b"\xff\xd8\xff", ".jpg", "JPEG"),
        ("pdf", b"%PDF", ".pdf", "PDF"),
        ("elf", b"\x7fELF", ".elf", "ELF"),
        ("mz", b"MZ", ".exe", "PE/MZ"),
        ("sqlite", b"SQLite format 3\x00", ".sqlite", "SQLite"),
        ("rar", b"Rar!\x1a\x07", ".rar", "RAR"),
        ("7z", b"7z\xbc\xaf\x27\x1c", ".7z", "7z"),
    ]
def sl54_carve_region(data, off, kind):
    data=bytes(data)
    if kind=="png":
        end=data.find(b"IEND",off)
        if end!=-1:
            return data[off:end+8]
    if kind=="jpg":
        end=data.find(b"\xff\xd9",off+2)
        if end!=-1:
            return data[off:end+2]
    if kind=="pdf":
        end=data.find(b"%%EOF",off)
        if end!=-1:
            return data[off:end+5]
    # For archives/binaries without reliable end, carve bounded tail.
    return data[off:min(len(data), off+8_000_000)]
def sl54_light_child_scan(root, report, path, raw, kind_name):
    txt=raw[:500000].decode("utf-8","ignore")
    child={"path":str(path),"name":Path(path).name,"kind":kind_name,"size":len(raw),"flags":[],"strings":[]}
    try:
        child["strings"]=py_strings(raw,limit=250)
    except Exception:
        pass
    try:
        child["flags"]=vf_primary_flags(txt,limit=10,scan_limit=500000)
        for f in child["flags"]:
            if f not in report.setdefault("flags",[]):
                report["flags"].append(f)
    except Exception:
        pass
    sl54_promote_text(report,txt,"SLOPER v54 carved child",str(path),310)
    # Run downstream families based on magic.
    try:
        if kind_name in ["ZIP/APK/DOCX/JAR","Gzip","BZip2","XZ"]:
            sf_embedded_compression_agent(report,root,raw)
    except Exception:
        pass
    try:
        if kind_name=="SQLite":
            sl53_sqlite_agent(report,root,raw)
    except Exception:
        pass
    try:
        if kind_name in ["PNG","JPEG"]:
            fake=dict(report); fake["name"]=Path(path).name; fake["path"]=str(path); fake["kind"]="image"
            sl51_png_advanced_agent(fake,root,raw)
            for a in fake.get("artifacts",[])[:25]:
                if a not in report.setdefault("artifacts",[]):
                    report["artifacts"].append(a)
            for f in fake.get("flags",[]):
                if f not in report.setdefault("flags",[]):
                    report["flags"].append(f)
    except Exception:
        pass
    return child
def sl54_magic_carve_agent(report, root, data):
    data=bytes(data or b"")
    if len(data)<64 or len(data)>80_000_000:
        return []
    arts=[]
    found=[]
    outdir=root/"generated"/"sloper54"/safe(report.get("name","file"))/"magic_carves"
    outdir.mkdir(parents=True,exist_ok=True)
    for kind,sig,ext,label in sl54_magic_signatures():
        start=0
        hits=0
        while True:
            off=data.find(sig,start)
            if off==-1:
                break
            start=off+1
            # skip if same signature at offset 0 and this is simply the original file
            if off==0 and len(found)==0:
                continue
            hits+=1
            if hits>20:
                break
            raw=sl54_carve_region(data,off,kind)
            if len(raw)<len(sig):
                continue
            name=f"offset_{off:08x}_{kind}{ext}"
            p=outdir/name
            try:
                p.write_bytes(raw)
                art={"kind":"sloper54_magic_carved_child","name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v54","score":390,"note":f"Carved embedded {label} at offset {off} ({hex(off)})","exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
                report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art)
                child=sl54_light_child_scan(root,report,p,raw,label)
                found.append({"offset":off,"hex":hex(off),"kind":kind,"label":label,"path":str(p),"size":len(raw),"flags":child.get("flags",[])})
            except Exception as e:
                found.append({"offset":off,"kind":kind,"error":str(e)})
    if found:
        mart=sl54_art(root,report,"magic_carve_manifest.json",json.dumps({"carves":found},indent=2,ensure_ascii=False),"sloper54_magic_carve_manifest",430,"Embedded magic carve manifest with child analysis.")
        if mart:
            arts.insert(0,mart)
        report.setdefault("next_steps",[]).insert(0,{"priority":99,"step":"Open magic_carve_manifest.json and magic_carves/.","why":"v54 carved embedded child files and ran light downstream analysis on them."})
        sl54_trace(report,"MagicCarve",f"{len(found)} embedded magic regions carved",430,mart.get("path") if mart else "")
    return arts
def sl54_constant_array_agent(report, root, data):
    # Handles source/disassembly-like text and raw strings containing byte arrays.
    if len(data)>8_000_000:
        return []
    text=data[:2_000_000].decode("utf-8","ignore")
    if not text:
        return []
    arrays=[]
    # C/Python/JS style hex or decimal byte arrays.
    for m in re.finditer(r"(?:0x[0-9a-fA-F]{1,2}\s*,?\s*){6,}",text):
        vals=[int(x,16)&255 for x in re.findall(r"0x([0-9a-fA-F]{1,2})",m.group(0))]
        if 6<=len(vals)<=4096:
            arrays.append({"source":"hex_array","values":vals})
    for m in re.finditer(r"\{?((?:\d{1,3}\s*,\s*){6,}\d{1,3})\}?",text):
        vals=[int(x)&255 for x in re.findall(r"\d{1,3}",m.group(1))]
        if 6<=len(vals)<=4096 and all(0<=v<=255 for v in vals):
            arrays.append({"source":"dec_array","values":vals})
    # Escaped byte strings.
    for m in re.finditer(r"(?:\\x[0-9a-fA-F]{2}){6,}",text):
        vals=[int(x,16) for x in re.findall(r"\\x([0-9a-fA-F]{2})",m.group(0))]
        arrays.append({"source":"escaped_hex","values":vals})
    if not arrays:
        return []
    outs=[]
    keys=[0x01,0x02,0x03,0x10,0x20,0x21,0x30,0x37,0x42,0x52,0x55,0x66,0x69,0x7f,0xaa,0xff]
    # derive keys from text
    for m in re.finditer(r"0x([0-9a-fA-F]{1,2})",text[:20000]):
        try:
            k=int(m.group(1),16)&255
            if k not in keys: keys.append(k)
        except Exception:
            pass
    for arr in arrays[:80]:
        vals=bytes(arr["values"])
        candidates=[("raw",vals,None),("reverse",vals[::-1],None),("not",bytes((~b)&255 for b in vals),None)]
        for k in keys:
            candidates.append((f"xor_{k:02x}",bytes(b^k for b in vals),k))
            candidates.append((f"add_{k:02x}",bytes((b+k)&255 for b in vals),k))
            candidates.append((f"sub_{k:02x}",bytes((b-k)&255 for b in vals),k))
        for method,bs,k in candidates:
            txt="".join(chr(b) if 32<=b<127 or b in (9,10,13) else "." for b in bs)
            score=sl43_text_quality(txt)
            if score>80 or "ctf" in txt.lower() or "{" in txt or re.search(r"[a-z0-9]{2,}_[a-z0-9_]{2,}",txt.lower()):
                outs.append({"array_source":arr["source"],"length":len(vals),"method":method,"key":k,"score":score,"text":txt[:2000],"hex_head":bs[:64].hex()})
                sl54_promote_text(report,txt,"SLOPER v54 constant-array solver",None,300)
    if outs:
        # dedup
        ded=[]; seen=set()
        for o in sorted(outs,key=lambda x:x["score"],reverse=True):
            sig=(o["method"],o["text"][:100])
            if sig not in seen:
                seen.add(sig); ded.append(o)
            if len(ded)>=160:
                break
        art=sl54_art(root,report,"constant_array_decode_candidates.json",json.dumps(ded,indent=2,ensure_ascii=False),"sloper54_constant_array_decode",370,"Byte/int array decode candidates using raw/reverse/NOT/XOR/ADD/SUB.")
        if art:
            report.setdefault("next_steps",[]).insert(0,{"priority":96,"step":"Review constant_array_decode_candidates.json.","why":"v54 found byte/int arrays and decoded them through common reversing transforms."})
            return [art]
    return []
def sl54_run_agents(report, root, data):
    arts=[]
    for fn,name in [
        (sl54_magic_carve_agent,"magic carve"),
        (sl54_constant_array_agent,"constant arrays"),
        (sl54_entropy_map_agent,"entropy map"),
    ]:
        try:
            arts += fn(report,root,data) or []
        except Exception as e:
            sl54_trace(report,name+" failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v54 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v54(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl54_trace(report,"previous agents failed",str(e),0)
    try:
        arts += sl54_run_agents(report,root,data) or []
    except Exception as e:
        sl54_trace(report,"v54 agents failed",str(e),0)
    return arts
_prev_project_summary_v54 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v54(reports, meta)
    artifacts=summary.get("artifacts",[]) or []
    lane=summary.get("sloper53_review_lanes",{}) or summary.get("sloper52_review_lanes",{}) or summary.get("sloper51_review_lanes",{}) or {}
    lane["v54_magic_carves"]=len([a for a in artifacts if "sloper54_magic" in a.get("kind","") or "magic_carve_manifest" in a.get("name","")])
    lane["v54_constant_arrays"]=len([a for a in artifacts if "constant_array" in a.get("name","") or "sloper54_constant" in a.get("kind","")])
    lane["v54_entropy_maps"]=len([a for a in artifacts if "entropy_offset_map" in a.get("name","")])
    summary["sloper54_review_lanes"]=lane
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper54" in txt or "v54" in txt: s+=10000
        if "magic_carve_manifest" in txt: s+=2200
        if "constant_array" in txt: s+=1800
        if "entropy_offset_map" in txt: s+=700
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(artifacts,key=pri,reverse=True)[:6000]
    brief=summary.get("sloper53_project_brief",{}) or summary.get("sloper52_project_brief",{}) or {}
    brief["v54_deep_carve"]="active"
    if lane.get("v54_magic_carves"): brief["inspect_first"]="magic_carve_manifest.json"
    elif lane.get("v54_constant_arrays"): brief["inspect_first"]="constant_array_decode_candidates.json"
    elif lane.get("v54_entropy_maps") and not summary.get("flags"): brief["inspect_first"]="entropy_offset_map.json"
    summary["sloper54_project_brief"]=brief
    matrix=summary.get("sloper53_coverage_matrix",{}) or {}
    matrix["magic_carving_v54"]=lane.get("v54_magic_carves",0)
    matrix["constant_arrays"]=lane.get("v54_constant_arrays",0)
    matrix["entropy_maps"]=lane.get("v54_entropy_maps",0)
    summary["sloper54_coverage_matrix"]=matrix
    na=summary.get("sloper53_next_actions",[]) or summary.get("workflow_steps",[]) or []
    if lane.get("v54_magic_carves"):
        na.insert(0,{"priority":100,"step":"Open magic_carve_manifest.json first.","why":"v54 carved embedded child files and ran light downstream analysis on them."})
    if lane.get("v54_constant_arrays"):
        na.insert(0,{"priority":97,"step":"Open constant_array_decode_candidates.json.","why":"v54 decoded byte/int arrays through raw/reverse/NOT/XOR/ADD/SUB transforms."})
    summary["sloper54_next_actions"]=na[:46]
    summary["workflow_steps"]=na[:46]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v54"
def sl55_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl54_trace(report, "v55:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v55:"+str(stage),
            "detail":str(detail)[:1800],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl55_art(root, report, name, content, kind="sloper55_artifact", score=240, note=""):
    outdir=root/"generated"/"sloper55"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v55","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl55_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl55_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl55_promote_text(report, text, source, artifact=None, score=290):
    try:
        sl45_promote_answer_markers(report,text,source,artifact,score)
    except Exception:
        pass
    try:
        for f in vf_primary_flags(str(text),limit=10,scan_limit=400000):
            if f not in report.setdefault("flags",[]):
                report["flags"].append(f)
                sl55_trace(report,"strict flag",f,score,artifact,f)
    except Exception:
        pass
def sl55_printable(bs):
    bs=bytes(bs or b"")
    return "".join(chr(b) if 32<=b<127 or b in (9,10,13) else "." for b in bs)
def sl55_quality_bytes(bs):
    bs=bytes(bs or b"")
    if not bs:
        return 0
    txt=sl55_printable(bs[:200000])
    try:
        score=sl43_text_quality(txt)
    except Exception:
        printable=sum(1 for c in txt if c!=".")/max(1,len(txt))
        score=int(printable*100)
    low=txt.lower()
    for w in ["ctf_cs{","flag{","secret","password","cyber","sprint","raktas","slapta","token"]:
        if w in low:
            score += 120
    if "{" in txt and "}" in txt:
        score += 70
    return score
def sl55_decode_candidates_from_text(s):
    import base64, urllib.parse, zlib, gzip, bz2, lzma
    s=str(s or "").strip()
    out=[]
    if not s:
        return out
    try:
        u=urllib.parse.unquote_plus(s)
        if u and u!=s:
            out.append(("url_decode",u.encode()))
    except Exception:
        pass
    compact=re.sub(r"\s+","",s)
    if len(compact)>=8 and len(compact)%2==0 and re.fullmatch(r"[0-9a-fA-F]+",compact):
        try:
            out.append(("hex",bytes.fromhex(compact)))
        except Exception:
            pass
    if len(compact)>=8 and len(compact)%8==0 and re.fullmatch(r"[01]+",compact):
        try:
            out.append(("binary", bytes(int(compact[i:i+8],2) for i in range(0,len(compact),8))))
        except Exception:
            pass
    toks=re.findall(r"\b\d{1,3}\b",s)
    if len(toks)>=4:
        try:
            vals=[int(x) for x in toks]
            if all(0<=v<=255 for v in vals):
                out.append(("decimal_bytes",bytes(vals)))
            if all(0<=v<=377 for v in vals) and any(x.startswith("0") for x in toks):
                out.append(("octal_bytes",bytes(int(x,8)&255 for x in toks)))
        except Exception:
            pass
    if len(compact)>=8 and re.fullmatch(r"[A-Za-z0-9+/=_-]+",compact):
        for name,fn in [
            ("base64",base64.b64decode),
            ("urlsafe_base64",base64.urlsafe_b64decode),
            ("base32",base64.b32decode),
            ("base85",base64.b85decode),
            ("ascii85",base64.a85decode),
        ]:
            for pad in ["","=","==","===","===="]:
                try:
                    raw=fn(compact+pad)
                    if raw and raw!=s.encode():
                        out.append((name,raw))
                        break
                except Exception:
                    pass
    raw0=s.encode("utf-8","ignore")
    for name,fn in [("zlib",zlib.decompress),("gzip",gzip.decompress),("bz2",bz2.decompress),("lzma",lzma.decompress)]:
        try:
            raw=fn(raw0)
            if raw:
                out.append((name,raw))
        except Exception:
            pass
    return out
def sl55_decode_graph_agent(report, root, data):
    data=bytes(data or b"")
    if not data or len(data)>5_000_000:
        return []
    p=Path(report.get("path",""))
    ext=p.suffix.lower()
    kind=report.get("kind","")
    allow = kind in ["text","generic","archive","binary","python_bytecode","log","text_context"] or ext in [".txt",".dat",".enc",".log",".json",".csv",".md",".py",".js",".php",".bin",""]
    if not allow and len(data)>500000:
        return []
    seeds=[]
    text=data[:500000].decode("utf-8","ignore")
    if text.strip():
        seeds.append(("raw_text",text))
    try:
        for st in py_strings(data,limit=300):
            if 6<=len(st)<=5000:
                seeds.append(("string",st))
    except Exception:
        pass
    if len(data)<=200000:
        seeds.append(("file_hex",data.hex()))
    seen_text=set()
    nodes=[]
    queue=[]
    for src,s in seeds[:350]:
        k=s[:2000]
        if k not in seen_text:
            seen_text.add(k)
            queue.append({"source":src,"text":s,"path":[src],"depth":0})
    seen_raw=set()
    best=[]
    max_nodes=900
    while queue and len(nodes)<max_nodes:
        item=queue.pop(0)
        txt=item["text"]
        for method,raw in sl55_decode_candidates_from_text(txt):
            if not raw or len(raw)>2_000_000:
                continue
            h=hashlib.sha256(raw[:500000]).hexdigest()
            if h in seen_raw:
                continue
            seen_raw.add(h)
            out_text=raw[:500000].decode("utf-8","ignore")
            score=sl55_quality_bytes(raw)
            node={"path":item["path"]+[method],"method":method,"depth":item["depth"]+1,"size":len(raw),"score":score,"preview":sl55_printable(raw[:3000]),"hex_head":raw[:64].hex()}
            nodes.append(node)
            preview_low=node["preview"].lower()
            if score>=90 or "ctf" in preview_low or "{" in node["preview"]:
                best.append(node)
                sl55_promote_text(report,node["preview"],"SLOPER v55 decode graph",None,300+min(score,250))
            if item["depth"]<4 and (score>=40 or len(raw)<=200000):
                if out_text.strip() and out_text[:2000] not in seen_text:
                    seen_text.add(out_text[:2000])
                    queue.append({"source":method,"text":out_text,"path":item["path"]+[method],"depth":item["depth"]+1})
    if not nodes:
        return []
    result={"node_count":len(nodes),"best":sorted(best,key=lambda x:x["score"],reverse=True)[:80],"nodes":sorted(nodes,key=lambda x:x["score"],reverse=True)[:300]}
    art=sl55_art(root,report,"decode_graph.json",json.dumps(result,indent=2,ensure_ascii=False),"sloper55_decode_graph",380,"Recursive decode graph across common encodings/compressions.")
    if art:
        report.setdefault("next_steps",[]).insert(0,{"priority":98,"step":"Open decode_graph.json.","why":"v55 recursively decoded common CTF encodings and ranked readable/flag-like outputs."})
        return [art]
    return []
def sl55_generic_xor_agent(report, root, data):
    data=bytes(data or b"")
    if not data or len(data)>2_500_000:
        return []
    kind=report.get("kind","")
    hint=(ux_statement_text(report)+" "+report.get("name","")).lower()
    if kind=="image" and not any(k in hint for k in ["xor","encoded","užkodu","uzkodu"]):
        return []
    if kind=="pcap" and not any(k in hint for k in ["xor","encoded","užkodu","uzkodu"]):
        return []
    candidates=[]
    keys=list(range(256)) if len(data)<=300000 else [0x01,0x02,0x03,0x10,0x20,0x21,0x30,0x37,0x42,0x52,0x55,0x66,0x69,0x7f,0xaa,0xff]
    for k in keys:
        if k==0:
            continue
        raw=bytes(b^k for b in data[:800000])
        score=sl55_quality_bytes(raw)
        txt=sl55_printable(raw[:5000])
        try:
            magic=sl50_magic_kind(raw)
        except Exception:
            magic=[]
        low=txt.lower()
        if score>=120 or magic or "ctf_cs{" in low or "flag{" in low:
            candidates.append({"method":"xor_single_byte","key":k,"key_hex":f"0x{k:02x}","score":score+(250 if magic else 0),"magic":magic,"preview":txt[:4000],"hex_head":raw[:64].hex()})
            sl55_promote_text(report,txt,"SLOPER v55 generic XOR",None,330)
    if not candidates:
        return []
    candidates=sorted(candidates,key=lambda x:x["score"],reverse=True)[:80]
    art=sl55_art(root,report,"generic_xor_candidates.json",json.dumps(candidates,indent=2,ensure_ascii=False),"sloper55_generic_xor_candidates",360,"Generic single-byte XOR candidates over file bytes.")
    if art:
        report.setdefault("next_steps",[]).insert(0,{"priority":96,"step":"Open generic_xor_candidates.json.","why":"v55 found readable/magic/flag-like single-byte XOR decodes."})
        return [art]
    return []
def sl55_run_agents(report, root, data):
    arts=[]
    for fn,name in [
        (sl55_decode_graph_agent,"decode graph"),
        (sl55_generic_xor_agent,"generic xor"),
    ]:
        try:
            arts += fn(report,root,data) or []
        except Exception as e:
            sl55_trace(report,name+" failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v55 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v55(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl55_trace(report,"previous agents failed",str(e),0)
    try:
        arts += sl55_run_agents(report,root,data) or []
    except Exception as e:
        sl55_trace(report,"v55 agents failed",str(e),0)
    return arts
_prev_project_summary_v55 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v55(reports, meta)
    artifacts=summary.get("artifacts",[]) or []
    lane=summary.get("sloper54_review_lanes",{}) or summary.get("sloper53_review_lanes",{}) or {}
    lane["v55_decode_graphs"]=len([a for a in artifacts if "decode_graph" in a.get("name","")])
    lane["v55_generic_xor"]=len([a for a in artifacts if "generic_xor" in a.get("name","") or "sloper55_generic_xor" in a.get("kind","")])
    summary["sloper55_review_lanes"]=lane
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper55" in txt or "v55" in txt: s+=11200
        if "decode_graph" in txt: s+=2400
        if "generic_xor" in txt: s+=1700
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(artifacts,key=pri,reverse=True)[:6500]
    brief=summary.get("sloper54_project_brief",{}) or summary.get("sloper53_project_brief",{}) or {}
    brief["v55_decode_pipeline"]="active"
    if lane.get("v55_decode_graphs"): brief["inspect_first"]="decode_graph.json"
    elif lane.get("v55_generic_xor"): brief["inspect_first"]="generic_xor_candidates.json"
    summary["sloper55_project_brief"]=brief
    matrix=summary.get("sloper54_coverage_matrix",{}) or summary.get("sloper53_coverage_matrix",{}) or {}
    matrix["decode_graphs"]=lane.get("v55_decode_graphs",0)
    matrix["generic_xor"]=lane.get("v55_generic_xor",0)
    summary["sloper55_coverage_matrix"]=matrix
    na=summary.get("sloper54_next_actions",[]) or summary.get("workflow_steps",[]) or []
    if lane.get("v55_decode_graphs"):
        na.insert(0,{"priority":100,"step":"Open decode_graph.json first.","why":"v55 recursively decoded common encodings/compressions and ranked best outputs."})
    if lane.get("v55_generic_xor"):
        na.insert(0,{"priority":98,"step":"Open generic_xor_candidates.json.","why":"v55 found readable/magic/flag-like single-byte XOR decodes."})
    summary["sloper55_next_actions"]=na[:50]
    summary["workflow_steps"]=na[:50]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v55"
def sl56_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl55_trace(report, "v56:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v56:"+str(stage),
            "detail":str(detail)[:1800],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl56_art(root, report, name, content, kind="sloper56_artifact", score=250, note=""):
    outdir=root/"generated"/"sloper56"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v56","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl56_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl56_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl56_promote_text(report, text, source, artifact=None, score=300):
    try:
        sl45_promote_answer_markers(report,text,source,artifact,score)
    except Exception:
        pass
    try:
        for f in vf_primary_flags(str(text),limit=12,scan_limit=500000):
            if f not in report.setdefault("flags",[]):
                report["flags"].append(f)
                sl56_trace(report,"strict flag",f,score,artifact,f)
    except Exception:
        pass
def sl56_printable(bs):
    return "".join(chr(b) if 32<=b<127 or b in (9,10,13) else "." for b in bytes(bs or b""))
def sl56_score_text(txt):
    try:
        sc=sl43_text_quality(txt)
    except Exception:
        sc=int(sum(1 for c in txt if 32<=ord(c)<127 or c in "\n\r\t")/max(1,len(txt))*100)
    low=txt.lower()
    for w in ["ctf_cs{","flag{","secret","password","token","cyber","sprint","raktas","slapta"]:
        if w in low:
            sc += 140
    if "{" in txt and "}" in txt:
        sc += 80
    return sc
def sl56_repeating_xor_crib_agent(report, root, data):
    data=bytes(data or b"")
    if not data or len(data)>2_000_000:
        return []
    kind=report.get("kind","")
    hint=(ux_statement_text(report)+" "+report.get("name","")).lower()
    if kind in ["image","pcap"] and not any(k in hint for k in ["xor","key","crib","known","užkodu","uzkodu","encoded"]):
        return []
    cribs=[b"ctf_cs{", b"flag{", b"CTF{", b"ctf{", b"cyber", b"sprint"]
    candidates=[]
    max_off=min(len(data),4096)
    for crib in cribs:
        if len(data)<len(crib):
            continue
        for off in range(max_off):
            seg=data[off:off+len(crib)]
            if len(seg)<len(crib):
                break
            keyseg=bytes(seg[i]^crib[i] for i in range(len(crib)))
            for keylen in range(1,33):
                ok=True
                key=[None]*keylen
                for i,kb in enumerate(keyseg):
                    pos=(off+i)%keylen
                    if key[pos] is None:
                        key[pos]=kb
                    elif key[pos]!=kb:
                        ok=False
                        break
                if not ok:
                    continue
                # Fill unknown key slots with common bytes? Better only use fully known short keys.
                if any(x is None for x in key):
                    continue
                kbytes=bytes(key)
                raw=bytes(data[i]^kbytes[i%keylen] for i in range(min(len(data),600000)))
                txt=sl56_printable(raw[:200000])
                score=sl56_score_text(txt)
                if score>=160 or "ctf_cs{" in txt.lower() or "flag{" in txt.lower():
                    candidates.append({"crib":crib.decode("utf-8","ignore"),"offset":off,"key_len":keylen,"key_hex":kbytes.hex(),"key_ascii":sl56_printable(kbytes),"score":score,"preview":txt[:5000]})
                    sl56_promote_text(report,txt,"SLOPER v56 crib XOR",None,340+min(score,200))
    if not candidates:
        return []
    # Dedup
    out=[]; seen=set()
    for c in sorted(candidates,key=lambda x:x["score"],reverse=True):
        k=(c["offset"],c["key_len"],c["key_hex"],c["preview"][:80])
        if k not in seen:
            seen.add(k); out.append(c)
        if len(out)>=100:
            break
    art=sl56_art(root,report,"crib_xor_candidates.json",json.dumps(out,indent=2,ensure_ascii=False),"sloper56_crib_xor_candidates",390,"Known-plaintext/repeating-key XOR candidates using flag prefixes as cribs.")
    if art:
        report.setdefault("next_steps",[]).insert(0,{"priority":99,"step":"Open crib_xor_candidates.json.","why":"v56 used known flag prefixes as XOR cribs and recovered possible repeating keys."})
        return [art]
    return []
def sl56_jwt_token_agent(report, root, data):
    text=data[:2_000_000].decode("utf-8","ignore")
    toks=re.findall(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)?\b",text)
    if not toks:
        try:
            for s in report.get("strings",[])[:500]:
                toks += re.findall(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)?\b",s)
        except Exception:
            pass
    if not toks:
        return []
    import base64 as _b64
    decoded=[]
    def b64url(s):
        return _b64.urlsafe_b64decode(s+"="*((4-len(s)%4)%4))
    for tok in list(dict.fromkeys(toks))[:50]:
        parts=tok.split(".")
        obj={"token":tok,"parts":[]}
        for part in parts[:3]:
            try:
                raw=b64url(part)
                txt=raw.decode("utf-8","ignore")
                obj["parts"].append(txt)
            except Exception as e:
                obj["parts"].append("<decode error>")
        decoded.append(obj)
        sl56_promote_text(report,"\n".join(obj["parts"]),"SLOPER v56 JWT decode",None,300)
    art=sl56_art(root,report,"jwt_token_decode.json",json.dumps(decoded,indent=2,ensure_ascii=False),"sloper56_jwt_token_decode",350,"JWT/token base64url decoded headers/payloads.")
    if art:
        report.setdefault("next_steps",[]).insert(0,{"priority":93,"step":"Open jwt_token_decode.json.","why":"v56 decoded JWT-like tokens and scanned payloads for flags/secrets."})
        return [art]
    return []
def sl56_image_bitplane_agent(report, root, data):
    p=Path(report.get("path",""))
    if report.get("kind")!="image" and p.suffix.lower() not in [".png",".bmp",".gif",".jpg",".jpeg",".webp"]:
        return []
    if len(data)>12_000_000:
        return []
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return []
    try:
        img=Image.open(p); img.load()
    except Exception:
        return []
    w,h=img.size
    if w*h>2_500_000:
        return []
    try:
        rgba=img.convert("RGBA")
        channels=[("R",0),("G",1),("B",2),("A",3)]
        planes=[]
        labels=[]
        thumb=(180,140)
        for cname,idx in channels:
            for bit in range(8):
                plane=Image.new("L",rgba.size,0)
                pix=[]
                for px in rgba.getdata():
                    pix.append(255 if ((px[idx]>>bit)&1) else 0)
                plane.putdata(pix)
                # autocontrast not needed for binary
                planes.append(plane)
                labels.append(f"{cname} bit {bit}")
        cols=4
        label_h=22
        rows=(len(planes)+cols-1)//cols
        sheet=Image.new("RGB",(cols*thumb[0],rows*(thumb[1]+label_h)),"white")
        draw=ImageDraw.Draw(sheet)
        for i,pl in enumerate(planes):
            c=i%cols; r=i//cols
            im=pl.convert("RGB")
            im.thumbnail(thumb)
            x=c*thumb[0]+(thumb[0]-im.width)//2
            y=r*(thumb[1]+label_h)
            sheet.paste(im,(x,y))
            draw.text((c*thumb[0]+6,y+thumb[1]+3),labels[i],fill=(0,0,0))
        outdir=root/"generated"/"sloper56"/safe(report.get("name","file"))
        outdir.mkdir(parents=True,exist_ok=True)
        sp=outdir/"bitplane_contact_sheet.png"
        sheet.save(sp)
        art={"kind":"sloper56_bitplane_contact_sheet","name":sp.name,"path":str(sp),"url":"/api/raw?path="+str(sp),"source":"CTF SLOPER v56","score":360,"note":"R/G/B/A bitplane contact sheet for visual stego review.","exists":True,"size":sp.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).insert(0,art); report.setdefault("transformations",[]).insert(0,art)
        report.setdefault("next_steps",[]).insert(0,{"priority":96,"step":"Open bitplane_contact_sheet.png.","why":"v56 generated R/G/B/A bitplanes; hidden text/images often appear in a single bitplane."})
        return [art]
    except Exception as e:
        sl56_trace(report,"bitplane failed",str(e),0)
        return []
