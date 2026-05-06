# Auto-split from sloper_legacy_monolith.py lines 16843-...
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v51(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl51_trace(report,"previous agents failed",str(e),0)
    try:
        arts += sl51_run_agents(report,root,data) or []
    except Exception as e:
        sl51_trace(report,"v51 agents failed",str(e),0)
    return arts
_prev_project_summary_v51 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v51(reports, meta)
    artifacts=summary.get("artifacts",[]) or []
    lane=summary.get("sloper50_review_lanes",{}) or summary.get("sloper49_review_lanes",{}) or {}
    lane["v51_pyc_backdoor"]=len([a for a in artifacts if "pyc_backdoor" in a.get("name","")])
    lane["v51_recursive_zip"]=len([a for a in artifacts if "recursive_zip" in a.get("name","")])
    lane["v51_pure_pcap"]=len([a for a in artifacts if "pure_pcap" in a.get("name","")])
    lane["v51_png_streams"]=len([a for a in artifacts if "png_advanced" in a.get("name","") or "png_stream" in a.get("kind","")])
    summary["sloper51_review_lanes"]=lane
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper51" in txt or "v51" in txt: s+=7600
        if any(k in txt for k in ["pyc_backdoor","recursive_zip","pure_pcap","png_advanced","png_stream"]): s+=1600
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(artifacts,key=pri,reverse=True)[:5000]
    brief=summary.get("sloper50_project_brief",{}) or summary.get("sloper49_project_brief",{}) or {}
    brief["v51_coverage"]="active"
    if lane.get("v51_pyc_backdoor"): brief["inspect_first"]="pyc_backdoor_analysis.json"
    elif lane.get("v51_recursive_zip"): brief["inspect_first"]="recursive_zip_path_analysis.json"
    elif lane.get("v51_pure_pcap"): brief["inspect_first"]="pure_pcap_covert_analysis.json"
    elif lane.get("v51_png_streams"): brief["inspect_first"]="png_advanced_streams_manifest.json"
    summary["sloper51_project_brief"]=brief
    na=summary.get("sloper50_next_actions",[]) or summary.get("workflow_steps",[]) or []
    if lane.get("v51_pyc_backdoor"):
        na.insert(0,{"priority":99,"step":"Open pyc_backdoor_analysis.json.","why":"v51 decoded PYC constants/base64 and generated phrase+CWE candidates."})
    if lane.get("v51_recursive_zip"):
        na.insert(0,{"priority":98,"step":"Open recursive_zip_path_analysis.json.","why":"v51 analyzed nested ZIP path names and long phrase candidates."})
    if lane.get("v51_pure_pcap"):
        na.insert(0,{"priority":97,"step":"Open pure_pcap_covert_analysis.json.","why":"v51 parsed PCAP fields without tshark and extracted covert candidates."})
    if lane.get("v51_png_streams"):
        na.insert(0,{"priority":96,"step":"Open PNG stream artifacts.","why":"v51 extracted alpha/RGB/hue-sorted streams from PNG."})
    summary["sloper51_next_actions"]=na[:38]
    summary["workflow_steps"]=na[:38]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v51"
def sl51_parse_pcap_rawip(data):
    import struct
    if len(data)<24:
        return []
    magic=data[:4]
    if magic==b"\xd4\xc3\xb2\xa1": endian="<"
    elif magic==b"\xa1\xb2\xc3\xd4": endian=">"
    else: return []
    off=24
    rows=[]
    idx=0
    while off+16<=len(data) and idx<50000:
        try:
            ts,us,inc,orig=struct.unpack(endian+"IIII",data[off:off+16]); off+=16
            pkt=data[off:off+inc]; off+=inc; idx+=1
            if len(pkt)<20: continue
            vihl=pkt[0]; ver=vihl>>4; ihl=(vihl&15)*4
            if ver!=4 or ihl<20 or len(pkt)<ihl: continue
            total=struct.unpack("!H",pkt[2:4])[0]
            ipid=struct.unpack("!H",pkt[4:6])[0]
            ttl=pkt[8]; proto=pkt[9]
            src=".".join(map(str,pkt[12:16])); dst=".".join(map(str,pkt[16:20]))
            payload=pkt[ihl:min(total,len(pkt))]
            rows.append({"idx":idx,"ts":ts,"us":us,"len":total,"ipid":ipid,"ttl":ttl,"proto":proto,"src":src,"dst":dst,"payload_hex":payload.hex(),"payload":payload})
        except Exception:
            break
    return rows
def sl51_pcap_pure_agent(report, root, data):
    import struct
    p=Path(report.get("path",""))
    if p.suffix.lower() not in [".pcap",".pcapng"] and report.get("kind")!="pcap":
        return []
    rows=sl51_parse_pcap_rawip(data)
    if not rows:
        return []
    arts=[]
    import collections as _collections
    summary={
        "packet_count":len(rows),
        "proto_counts":dict(_collections.Counter(r["proto"] for r in rows)),
        "ttl_counts":dict(_collections.Counter(r["ttl"] for r in rows)),
        "flow_counts":{str(k):v for k,v in _collections.Counter((r["src"],r["dst"],r["proto"]) for r in rows).most_common(20)},
    }
    candidates=[]
    fields={
        "ttl":[r["ttl"] for r in rows],
        "src_last":[int(r["src"].split(".")[-1]) for r in rows],
        "dst_last":[int(r["dst"].split(".")[-1]) for r in rows],
        "usec_low":[r["us"]&255 for r in rows],
        "payload0":[r["payload"][0] if r["payload"] else 0 for r in rows],
        "proto":[r["proto"] for r in rows],
    }
    for name,vals in fields.items():
        for variant,arr in [("raw",vals),("diff",[(vals[i]-vals[i-1])&255 for i in range(1,len(vals))]),("mod95",[(v%95)+32 for v in vals])]:
            txt="".join(chr(x) if 32<=x<127 else "." for x in arr[:5000])
            if sl43_text_quality(txt)>80 or any(k in txt.lower() for k in ["ctf","flag","secret","hidden","cyber","{"]):
                candidates.append({"field":name,"variant":variant,"preview":txt[:2000],"score":sl43_text_quality(txt)})
    decoded_payloads=[]
    for r in rows[:5000]:
        raw=r["payload"]
        if not raw: continue
        txt=raw.decode("utf-8","ignore")
        if txt and (sl43_text_quality(txt)>60 or any(k in txt.lower() for k in ["ctf","flag","secret","internal","service","{"])):
            decoded_payloads.append({"idx":r["idx"],"proto":r["proto"],"src":r["src"],"dst":r["dst"],"text":txt[:500]})
            sl51_promote_text(report,txt,"SLOPER v51 PCAP payload",None,260)
    icmp=[r for r in rows if r["proto"]==1]
    if icmp:
        last_bytes=[r["payload"][-1] for r in icmp if r["payload"]]
        txt="".join(chr(x) if 32<=x<127 else "." for x in last_bytes)
        candidates.append({"field":"icmp_payload_last_byte","variant":"ascii","preview":txt,"score":sl43_text_quality(txt)})
        sl51_promote_text(report,txt,"SLOPER v51 ICMP last-byte channel",None,280)
    tcp=[r for r in rows if r["proto"]==6 and len(r["payload"])>=4]
    if tcp:
        srcports=[struct.unpack("!H",r["payload"][:2])[0] for r in tcp]
        dstports=[struct.unpack("!H",r["payload"][2:4])[0] for r in tcp]
        for name,vals in [("tcp_srcport_low", [x&255 for x in srcports]),("tcp_dstport_low",[x&255 for x in dstports])]:
            txt="".join(chr(x) if 32<=x<127 else "." for x in vals)
            candidates.append({"field":name,"variant":"ascii","preview":txt[:1000],"score":sl43_text_quality(txt)})
            sl51_promote_text(report,txt,"SLOPER v51 TCP port channel",None,250)
    obj={"summary":summary,"field_candidates":candidates[:120],"decoded_payloads":decoded_payloads[:200]}
    art=sl51_art(root,report,"pure_pcap_covert_analysis.json",json.dumps(obj,indent=2,ensure_ascii=False),"sloper51_pure_pcap_covert_analysis",360,"Pure-Python PCAP covert-field extraction without tshark.")
    if art: arts.append(art)
    report.setdefault("next_steps",[]).insert(0,{"priority":97,"step":"Review pure_pcap_covert_analysis.json.","why":"v51 parsed PCAP without tshark and extracted IP/ICMP/TCP/UDP covert-field candidates."})
    sl51_trace(report,"PurePCAP",f"{len(rows)} packets parsed; {len(candidates)} field candidates",360,art.get("path") if art else "")
    return arts
def sl52_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl51_trace(report, "v52:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        report.setdefault("solve_trace", []).append({
            "stage":"SLOPER v52:"+str(stage),
            "detail":str(detail)[:1700],
            "confidence":int(confidence or 0),
            "artifact":artifact or "",
            "flag":flag or ""
        })
def sl52_art(root, report, name, content, kind="sloper52_artifact", score=220, note=""):
    outdir=root/"generated"/"sloper52"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v52","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl52_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl52_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl52_promote_text(report, text, source, artifact=None, score=280):
    try: sl45_promote_answer_markers(report,text,source,artifact,score)
    except Exception: pass
    try:
        for f in vf_primary_flags(str(text),limit=8,scan_limit=350000):
            if f not in report.setdefault("flags",[]):
                report["flags"].append(f)
                sl52_trace(report,"strict flag",f,score,artifact,f)
    except Exception:
        pass
def sl52_project_clue_words(root, reports=None, meta=None):
    blob=""
    try:
        if meta:
            blob += json.dumps(meta,ensure_ascii=False)+"\n"
    except Exception:
        pass
    try:
        for p in (Path(root)/"files").rglob("*"):
            if p.is_file() and p.stat().st_size<600000 and p.suffix.lower() in [".txt",".md",".log",".json",".csv"]:
                blob += p.read_text(encoding="utf-8",errors="ignore")+"\n"
    except Exception:
        pass
    if reports:
        for r in reports[:20]:
            try:
                blob += " ".join(r.get("strings",[])[:100])+"\n"
            except Exception:
                pass
    words=[]
    for w in re.findall(r"[A-Za-z0-9_@#$%+\-.]{3,64}",blob):
        wl=w.strip(".:-_")
        if 3<=len(wl)<=64:
            words.append(wl)
            words.append(wl.lower())
            words.append(wl.upper())
    # CTF defaults / common no-brute clue passwords.
    defaults=["password","secret","hidden","flag","ctf","cyber","sprint","cybersprint","slaptas","slapta","raktas","vilnius","admin","backdoor","treasure","lobis","key","pass","decode","stego"]
    words=defaults+words
    out=[]; seen=set()
    for w in words:
        if w and w not in seen:
            seen.add(w); out.append(w)
        if len(out)>=500:
            break
    return out
def sl52_entropy(data, window=4096, limit=80):
    import math
    data=bytes(data or b"")
    rows=[]
    for off in range(0,len(data),window):
        chunk=data[off:off+window]
        if not chunk: break
        counts=[0]*256
        for b in chunk: counts[b]+=1
        ent=0.0
        for c in counts:
            if c:
                p=c/len(chunk); ent-=p*math.log2(p)
        rows.append({"offset":off,"size":len(chunk),"entropy":round(ent,4),"ascii_ratio":round(sum(32<=b<127 or b in (9,10,13) for b in chunk)/len(chunk),4)})
        if len(rows)>=limit:
            break
    return rows
def sl52_entropy_triage_agent(report, root, data):
    if len(data)<2048:
        return []
    rows=sl52_entropy(data,4096,120)
    if not rows:
        return []
    high=[r for r in rows if r["entropy"]>7.7]
    text=[r for r in rows if r["ascii_ratio"]>0.75]
    obj={"file_size":len(data),"windows":rows,"high_entropy_windows":high[:40],"text_like_windows":text[:40]}
    art=sl52_art(root,report,"entropy_triage.json",json.dumps(obj,indent=2,ensure_ascii=False),"sloper52_entropy_triage",230,"Entropy/ascii windows for packed/encrypted/text regions.")
    if art:
        return [art]
    return []
def sl52_magic_signatures():
    return [
        ("zip",b"PK\x03\x04"),
        ("gzip",b"\x1f\x8b\x08"),
        ("bzip2",b"BZh"),
        ("xz",b"\xfd7zXZ\x00"),
        ("png",b"\x89PNG\r\n\x1a\n"),
        ("jpg",b"\xff\xd8\xff"),
        ("pdf",b"%PDF"),
        ("elf",b"\x7fELF"),
        ("mz",b"MZ"),
        ("sqlite",b"SQLite format 3\x00"),
        ("rar",b"Rar!\x1a\x07"),
        ("7z",b"7z\xbc\xaf\x27\x1c"),
    ]
def sl52_find_magic_offsets(data):
    data=bytes(data or b"")
    hits=[]
    for name,sig in sl52_magic_signatures():
        start=0
        while True:
            off=data.find(sig,start)
            if off<0: break
            hits.append({"kind":name,"offset":off,"sig":sig.hex()})
            start=off+1
            if len([h for h in hits if h["kind"]==name])>=30:
                break
    # TAR ustar at offset+257.
    start=0
    while True:
        off=data.find(b"ustar",start)
        if off<0: break
        if off>=257:
            hits.append({"kind":"tar","offset":off-257,"sig":"ustar@257"})
        start=off+1
        if len(hits)>200: break
    return sorted(hits,key=lambda x:x["offset"])[:200]
def sl52_extract_magic_blob(data, hit):
    data=bytes(data or b"")
    off=hit["offset"]; kind=hit["kind"]
    if off>=len(data): return b""
    # Use bounded tail by kind.
    maxlen={"zip":8_000_000,"gzip":8_000_000,"bzip2":8_000_000,"xz":8_000_000,"png":8_000_000,"jpg":8_000_000,"pdf":8_000_000,"elf":8_000_000,"mz":8_000_000,"sqlite":8_000_000,"rar":8_000_000,"7z":8_000_000,"tar":12_000_000}.get(kind,5_000_000)
    blob=data[off:off+maxlen]
    # Trim JPEG if possible.
    if kind=="jpg":
        end=blob.find(b"\xff\xd9")
        if end>=0: blob=blob[:end+2]
    # Trim PNG by IEND.
    if kind=="png":
        end=blob.find(b"IEND")
        if end>=0 and end+8<=len(blob): blob=blob[:end+8]
    return blob
def sl52_try_zip_passwords(root, report, blob, label):
    import zipfile as _zipfile, io as _io
    arts=[]
    try:
        z=_zipfile.ZipFile(_io.BytesIO(blob))
    except Exception:
        return arts
    words=sl52_project_clue_words(root)
    manifest={"label":label,"names":z.namelist()[:80],"encrypted":False,"attempts":[],"extracted":[]}
    try:
        encrypted=any((i.flag_bits & 0x1) for i in z.infolist())
        manifest["encrypted"]=encrypted
    except Exception:
        encrypted=False
    outdir=root/"generated"/"sloper52"/safe(report.get("name","file"))/"zip_password_extracts"/safe(label)
    outdir.mkdir(parents=True,exist_ok=True)
    # First no password.
    pwds=[None]+[w.encode("utf-8","ignore") for w in words[:350]]
    for pwd in pwds:
        ok=False
        extracted=[]
        try:
            for info in z.infolist()[:80]:
                if info.file_size>5_000_000 or info.is_dir(): continue
                raw=z.read(info, pwd=pwd)
                op=outdir/safe(info.filename.replace("/","_"))
                op.write_bytes(raw)
                extracted.append({"name":info.filename,"path":str(op),"size":len(raw),"password":pwd.decode("utf-8","ignore") if pwd else ""})
                txt=raw[:300000].decode("utf-8","ignore")
                sl52_promote_text(report,txt,"SLOPER v52 ZIP clue-password extraction",str(op),330)
            ok=True
        except Exception as e:
            manifest["attempts"].append({"password":pwd.decode("utf-8","ignore") if pwd else "", "ok":False, "error":str(e)[:120]})
        if ok and extracted:
            manifest["attempts"].append({"password":pwd.decode("utf-8","ignore") if pwd else "", "ok":True})
            manifest["extracted"]=extracted
            break
    art=sl52_art(root,report,f"zip_password_manifest_{safe(label)}.json",json.dumps(manifest,indent=2,ensure_ascii=False),"sloper52_zip_password_manifest",360 if manifest["extracted"] else 250,"ZIP password attempts using project clue wordlist.")
    if art: arts.append(art)
    return arts
def sl52_magic_carve_agent(report, root, data):
    hits=sl52_find_magic_offsets(data)
    # ignore offset 0 for same type unless multiple embedded files.
    p=Path(report.get("path",""))
    own_ext=p.suffix.lower()
    filtered=[]
    for h in hits:
        if h["offset"]==0 and len(hits)==1:
            continue
        filtered.append(h)
    if not filtered:
        return []
    arts=[]
    outdir=root/"generated"/"sloper52"/safe(report.get("name","file"))/"magic_carves"
    outdir.mkdir(parents=True,exist_ok=True)
    manifest=[]
    for i,h in enumerate(filtered[:40]):
        blob=sl52_extract_magic_blob(data,h)
        if len(blob)<4: continue
        fname=f"{i:02d}_off_{h['offset']:08x}_{h['kind']}.bin"
        op=outdir/fname
        try:
            op.write_bytes(blob)
        except Exception:
            continue
        txt=blob[:300000].decode("utf-8","ignore")
        flags=[]
        try: flags=vf_primary_flags(txt,limit=8,scan_limit=300000)
        except Exception: flags=[]
        for f in flags:
            if f not in report.setdefault("flags",[]): report["flags"].append(f)
        art={"kind":"sloper52_magic_carved_child","name":op.name,"path":str(op),"url":"/api/raw?path="+str(op),"source":"CTF SLOPER v52","score":390+(80 if flags else 0),"note":f"Magic carved {h['kind']} child at offset {h['offset']}.","exists":True,"size":op.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art); report.setdefault("transformations",[]).append(art); arts.append(art)
        manifest.append({"kind":h["kind"],"offset":h["offset"],"path":str(op),"size":len(blob),"flags":flags})
        try:
            if h["kind"]=="zip":
                arts += sl52_try_zip_passwords(root,report,blob,f"off_{h['offset']:x}")
        except Exception as e:
            sl52_trace(report,"ZIP password follow-up failed",str(e),0)
        try:
            if h["kind"] in ["gzip","bzip2","xz","zip","png","jpg","pdf","elf","mz"]:
                sf_embedded_compression_agent(report,root,blob)
        except Exception:
            pass
    if manifest:
        mart=sl52_art(root,report,"magic_carve_manifest.json",json.dumps(manifest,indent=2,ensure_ascii=False),"sloper52_magic_carve_manifest",420,"Magic offsets carved into child files and partially analyzed.")
        if mart: arts.insert(0,mart)
        report.setdefault("next_steps",[]).insert(0,{"priority":98,"step":"Open magic_carve_manifest.json and magic_carves/.","why":"v52 carved embedded files by magic headers and analyzed child content/passwords."})
    return arts
def sl52_parse_numeric_arrays(text):
    arrays=[]
    # C-style/JS/Python numeric arrays: 0x29, 31, ...
    for m in re.finditer(r"(?s)(?:unsigned\s+char|char|uint8_t|byte|bytes|array|buf|data|key)?[^;\n]{0,40}[\[{]\s*((?:0x[0-9a-fA-F]{1,2}|\d{1,3})\s*(?:,\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3})\s*){5,})[\]}]",text):
        nums=[]
        for tok in re.findall(r"0x[0-9a-fA-F]{1,2}|\d{1,3}",m.group(1)):
            try:
                v=int(tok,16) if tok.lower().startswith("0x") else int(tok)
                if 0<=v<=255: nums.append(v)
            except Exception:
                pass
        if len(nums)>=6:
            arrays.append(nums[:4096])
    # objdump immediates lines: mov BYTE PTR...,0x29 etc as contiguous blocks
    vals=[]
    for tok in re.findall(r"\b0x([0-9a-fA-F]{2})\b",text):
        vals.append(int(tok,16))
        if len(vals)>=6 and len(vals)%64==0:
            arrays.append(vals[-64:])
    if len(vals)>=6:
        arrays.append(vals[:4096])
    # dedupe
    out=[]; seen=set()
    for arr in arrays:
        h=hashlib.sha256(bytes(arr)).hexdigest()
        if h not in seen:
            seen.add(h); out.append(arr)
        if len(out)>=80: break
    return out
def sl52_transform_byte_array(arr):
    data=bytes(arr)
    cands=[]
    def add(method,key,bs):
        txt=bs.decode("utf-8","ignore")
        sc=sl43_text_quality(txt)
        if "ctf" in txt.lower() or "{" in txt or re.search(r"[a-z0-9]{2,}_[a-z0-9_]{2,}",txt.lower()) or sc>100:
            cands.append({"method":method,"key":key,"score":sc+(180 if "{" in txt else 0),"text":txt,"hex":bs[:128].hex()})
    for k in range(256):
        add("xor",k,bytes(b^k for b in data))
        if k in [1,2,3,4,7,8,13,16,32,42,52,85,127,128,255]:
            add("add",k,bytes((b+k)&255 for b in data))
            add("sub",k,bytes((b-k)&255 for b in data))
    add("not",None,bytes((~b)&255 for b in data))
    for n in range(1,8):
        add("rol",n,bytes(sl50_rol(b,n) for b in data))
        add("ror",n,bytes(sl50_ror(b,n) for b in data))
    out=[]; seen=set()
    for c in sorted(cands,key=lambda x:x["score"],reverse=True):
        k=c["text"]
        if k not in seen:
            seen.add(k); out.append(c)
        if len(out)>=80: break
    return out
def sl52_binary_constant_agent(report, root, data):
    p=Path(report.get("path",""))
    if len(data)>8_000_000:
        return []
    blob=""
    try: blob += "\n".join(report.get("strings",[])[:400])+"\n"
    except Exception: pass
    # Also include objdump/strings outputs if present.
    try:
        for o in report.get("outputs",[])[:80]:
            blob += (o.get("out") or "")[:200000]+"\n"
    except Exception:
        pass
    # If file is text/source/disassembly, include raw text.
    try:
        if p.suffix.lower() in [".txt",".c",".h",".py",".js",".asm",".s",".dump",".log"] or report.get("kind") in ["text","generic","binary"]:
            blob += data[:600000].decode("utf-8","ignore")
    except Exception:
        pass
    arrays=sl52_parse_numeric_arrays(blob)
    if not arrays:
        return []
    allc=[]
    for idx,arr in enumerate(arrays[:40]):
        cands=sl52_transform_byte_array(arr)
        for c in cands[:20]:
            c["array_index"]=idx; c["array_len"]=len(arr)
            allc.append(c)
    if not allc:
        return []
    allc=sorted(allc,key=lambda x:x["score"],reverse=True)[:160]
    art=sl52_art(root,report,"binary_constant_array_candidates.json",json.dumps(allc,indent=2,ensure_ascii=False),"sloper52_binary_constant_array_candidates",370,"Decoded candidates from numeric byte arrays using XOR/ADD/SUB/NOT/ROL/ROR.")
    if art:
        for c in allc[:20]:
            sl52_promote_text(report,c["text"],"SLOPER v52 binary constant array",art.get("path"),330)
        report.setdefault("next_steps",[]).insert(0,{"priority":97,"step":"Open binary_constant_array_candidates.json.","why":"v52 found numeric byte arrays and decoded them with common reversing transforms."})
        return [art]
    return []
def sl52_run_agents(report, root, data):
    arts=[]
    try: arts += sl52_entropy_triage_agent(report,root,data)
    except Exception as e: sl52_trace(report,"Entropy failed",str(e),0)
    try: arts += sl52_magic_carve_agent(report,root,data)
    except Exception as e: sl52_trace(report,"Magic carve failed",str(e),0)
    try: arts += sl52_binary_constant_agent(report,root,data)
    except Exception as e: sl52_trace(report,"Binary constants failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v52 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v52(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl52_trace(report,"previous agents failed",str(e),0)
    try:
        arts += sl52_run_agents(report,root,data) or []
    except Exception as e:
        sl52_trace(report,"v52 agents failed",str(e),0)
    return arts
_prev_project_summary_v52 = project_summary
def project_summary(reports, meta):
    summary=_prev_project_summary_v52(reports, meta)
    artifacts=summary.get("artifacts",[]) or []
    lane=summary.get("sloper51_review_lanes",{}) or summary.get("sloper50_review_lanes",{}) or {}
    lane["v52_magic_carves"]=len([a for a in artifacts if "magic_carve" in a.get("name","") or "magic_carved" in a.get("kind","")])
    lane["v52_zip_passwords"]=len([a for a in artifacts if "zip_password_manifest" in a.get("name","")])
    lane["v52_binary_constants"]=len([a for a in artifacts if "binary_constant_array" in a.get("name","")])
    lane["v52_entropy"]=len([a for a in artifacts if "entropy_triage" in a.get("name","")])
    summary["sloper52_review_lanes"]=lane
    # Coverage matrix.
    coverage=[]
    for r in reports:
        arts=r.get("artifacts",[])
        row={
            "file":r.get("rel") or r.get("name"),
            "kind":r.get("kind",""),
            "flags":len(r.get("flags",[]) or []),
            "wrappers":len(r.get("flag_wrapping_helpers",[]) or []),
            "artifacts":len(arts),
            "magic_carves":len([a for a in arts if "magic_carve" in a.get("name","") or "magic_carved" in a.get("kind","")]),
            "transformed_children":len([a for a in arts if "transformed_child" in a.get("kind","")]),
            "decode_candidates":len([a for a in arts if "decode" in a.get("name","") or "decode" in a.get("kind","")]),
            "recommended_first":""
        }
        if row["flags"]: row["recommended_first"]="Promoted flag evidence"
        elif row["magic_carves"]: row["recommended_first"]="magic_carve_manifest.json"
        elif row["transformed_children"]: row["recommended_first"]="transform_graph.json"
        elif row["decode_candidates"]: row["recommended_first"]="decode candidate artifact"
        elif arts: row["recommended_first"]=arts[0].get("name","artifact")
        else: row["recommended_first"]="manual inspection"
        coverage.append(row)
    summary["sloper52_coverage_matrix"]=coverage
    def pri(a):
        s=int(a.get("score",0) or 0)
        txt=(str(a.get("source",""))+" "+str(a.get("kind",""))+" "+str(a.get("name",""))).lower()
        if "sloper52" in txt or "v52" in txt: s+=8500
        if any(k in txt for k in ["magic_carve","zip_password","binary_constant","entropy_triage"]): s+=1800
        return (bool(a.get("exists",False)),s,int(a.get("size",0) or 0))
    summary["artifacts"]=sorted(artifacts,key=pri,reverse=True)[:5500]
    brief=summary.get("sloper51_project_brief",{}) or summary.get("sloper50_project_brief",{}) or {}
    brief["v52_generic_coverage"]="active"
    if lane.get("v52_magic_carves"): brief["inspect_first"]="magic_carve_manifest.json"
    elif lane.get("v52_binary_constants"): brief["inspect_first"]="binary_constant_array_candidates.json"
    elif lane.get("v52_zip_passwords"): brief["inspect_first"]="zip_password_manifest_*.json"
    summary["sloper52_project_brief"]=brief
    na=summary.get("sloper51_next_actions",[]) or summary.get("workflow_steps",[]) or []
    if lane.get("v52_magic_carves"):
        na.insert(0,{"priority":100,"step":"Open magic_carve_manifest.json first.","why":"v52 carved embedded child files from magic headers and partially analyzed them."})
    if lane.get("v52_binary_constants"):
        na.insert(0,{"priority":98,"step":"Open binary_constant_array_candidates.json.","why":"v52 found byte/int arrays and decoded them with XOR/ADD/SUB/ROL/ROR."})
    if lane.get("v52_zip_passwords"):
        na.insert(0,{"priority":97,"step":"Open ZIP password manifests.","why":"v52 tried project clue wordlist against embedded or uploaded ZIPs."})
    summary["sloper52_next_actions"]=na[:42]
    summary["workflow_steps"]=na[:42]+summary.get("workflow_steps",[])[:20]
    return summary
APP_TITLE = "CTF SLOPER v52"
def sl53_trace(report, stage, detail, confidence=0, artifact=None, flag=None):
    try:
        sl52_trace(report, "v53:"+str(stage), detail, confidence, artifact, flag)
    except Exception:
        try:
            sl51_trace(report, "v53:"+str(stage), detail, confidence, artifact, flag)
        except Exception:
            report.setdefault("solve_trace", []).append({
                "stage":"SLOPER v53:"+str(stage),
                "detail":str(detail)[:1600],
                "confidence":int(confidence or 0),
                "artifact":artifact or "",
                "flag":flag or ""
            })
def sl53_art(root, report, name, content, kind="sloper53_artifact", score=220, note=""):
    outdir=root/"generated"/"sloper53"/safe(report.get("name","file"))
    outdir.mkdir(parents=True, exist_ok=True)
    p=outdir/safe(name)
    try:
        if isinstance(content,(bytes,bytearray)):
            p.write_bytes(content)
        else:
            p.write_text(str(content),encoding="utf-8",errors="ignore")
        art={"kind":kind,"name":p.name,"path":str(p),"url":"/api/raw?path="+str(p),"source":"CTF SLOPER v53","score":int(score),"note":note or kind,"exists":True,"size":p.stat().st_size,"file":report.get("rel","")}
        report.setdefault("artifacts",[]).append(art)
        report.setdefault("transformations",[]).append(art)
        sl53_trace(report,"artifact",f"{kind}: {p.name}",score,str(p))
        return art
    except Exception as e:
        sl53_trace(report,"artifact failed",f"{name}: {e}",0)
        return None
def sl53_promote_text(report, text, source, artifact=None, score=280):
    try:
        sl45_promote_answer_markers(report,text,source,artifact,score)
    except Exception:
        pass
    try:
        for f in vf_primary_flags(str(text),limit=10,scan_limit=350000):
            if f not in report.setdefault("flags",[]):
                report["flags"].append(f)
                sl53_trace(report,"strict flag",f,score,artifact,f)
    except Exception:
        pass
def sl53_project_clue_wordlist(report):
    text=""
    try: text += ux_statement_text(report)+"\n"
    except Exception: pass
    try: text += "\n".join(report.get("strings",[])[:500])+"\n"
    except Exception: pass
    words=set()
    for tok in re.findall(r"[A-Za-z0-9_@#.$+\-]{3,64}",text):
        words.add(tok)
        words.add(tok.lower())
        words.add(tok.upper())
    # Useful CTF defaults from clues.
    for w in ["password","secret","flag","ctf","cyber","sprint","admin","root","hidden","slapta","raktas","pass","key","1234","12345","123456"]:
        words.add(w)
    # Add bodies from braces.
    for m in re.finditer(r"\{([^{}]{3,80})\}",text):
        body=m.group(1)
        words.add(body)
        words.add(body.replace("_",""))
    return [w for w in sorted(words,key=lambda x:(len(x),x)) if len(w)<=64][:600]
def sl53_zip_password_agent(report, root, data):
    import zipfile as _zipfile, io as _io
    if not _zipfile.is_zipfile(_io.BytesIO(data)):
        return []
    arts=[]
    wordlist=sl53_project_clue_wordlist(report)
    manifest={"tried":len(wordlist),"opened":[],"errors":[]}
    outbase=root/"generated"/"sloper53"/safe(report.get("name","file"))/"zip_password_extract"
    outbase.mkdir(parents=True,exist_ok=True)
    try:
        with _zipfile.ZipFile(_io.BytesIO(data)) as z:
            names=z.namelist()
            manifest["names"]=names[:200]
            # First try no password.
            for pwd in [None]+[w.encode("utf-8","ignore") for w in wordlist]:
                opened_this=[]
                for n in names[:200]:
                    try:
                        raw=z.read(n,pwd=pwd)
                        opened_this.append(n)
                        if len(raw)<5_000_000:
                            out=(outbase/safe((("nopass" if pwd is None else pwd.decode("utf-8","ignore"))+"_"+Path(n).name)[:120]))
                            out.write_bytes(raw)
                            art={"kind":"sloper53_zip_password_extracted","name":out.name,"path":str(out),"url":"/api/raw?path="+str(out),"source":"CTF SLOPER v53","score":360 if pwd else 280,"note":f"ZIP member extracted with password {pwd.decode('utf-8','ignore') if pwd else '<none>'}: {n}","exists":True,"size":out.stat().st_size,"file":report.get("rel","")}
                            report.setdefault("artifacts",[]).append(art); arts.append(art)
                            txt=raw[:300000].decode("utf-8","ignore")
                            sl53_promote_text(report,txt,"SLOPER v53 ZIP clue password",str(out),330 if pwd else 260)
                    except RuntimeError:
                        continue
                    except Exception as e:
                        continue
                if opened_this:
                    manifest["opened"].append({"password":pwd.decode("utf-8","ignore") if pwd else None,"members":opened_this[:50]})
                    if pwd is not None:
                        break
    except Exception as e:
        manifest["errors"].append(str(e))
    if manifest.get("opened"):
        art=sl53_art(root,report,"zip_password_manifest.json",json.dumps(manifest,indent=2,ensure_ascii=False),"sloper53_zip_password_manifest",380,"ZIP password/clue-wordlist extraction manifest.")
        if art: arts.insert(0,art)
        report.setdefault("next_steps",[]).insert(0,{"priority":97,"step":"Review zip_password_manifest.json and extracted ZIP children.","why":"v53 tried clue-derived passwords and extracted readable members."})
    return arts
def sl53_wav_audio_agent(report, root, data):
    p=Path(report.get("path",""))
    if p.suffix.lower() not in [".wav",".wave"] and b"WAVE" not in data[:64]:
        return []
    arts=[]
    try:
        import wave, io as _io
        wf=wave.open(_io.BytesIO(data),"rb")
        params={"channels":wf.getnchannels(),"sample_width":wf.getsampwidth(),"framerate":wf.getframerate(),"frames":wf.getnframes()}
        frames=wf.readframes(min(wf.getnframes(),1_000_000))
        wf.close()
    except Exception as e:
        sl53_trace(report,"WAV open failed",str(e),0)
        return []
    streams=[]
    for bit in [0,1]:
        bits="".join("1" if ((b>>bit)&1) else "0" for b in frames[:1_600_000])
        raw=sl48_bits_to_bytes(bits,max_bytes=200000) if "sl48_bits_to_bytes" in globals() else bytes(int(bits[i:i+8],2) for i in range(0,min(len(bits)//8,200000)*8,8))
        txt="".join(chr(b) if 32<=b<127 or b in (9,10,13) else "." for b in raw[:200000])
        score=sl43_text_quality(txt)
        if score>70 or "ctf" in txt.lower() or "{" in txt:
            art=sl53_art(root,report,f"wav_lsb_bit{bit}.txt",txt[:200000],"sloper53_wav_lsb_text",280+min(score,220),f"WAV byte LSB bit {bit} extraction.")
            if art:
                arts.append(art)
                sl53_promote_text(report,txt,"SLOPER v53 WAV LSB",art.get("path"),300)
            streams.append({"bit":bit,"score":score,"preview":txt[:2000]})
    manifest={"params":params,"streams":streams}
    art=sl53_art(root,report,"wav_lsb_manifest.json",json.dumps(manifest,indent=2,ensure_ascii=False),"sloper53_wav_lsb_manifest",250,"WAV/audio LSB extraction manifest.")
    if art: arts.append(art)
    return arts
def sl53_sqlite_agent(report, root, data):
    p=Path(report.get("path",""))
    if p.suffix.lower() not in [".db",".sqlite",".sqlite3"] and not data.startswith(b"SQLite format 3\x00"):
        return []
    arts=[]
    try:
        import sqlite3, tempfile
        tmp=root/"generated"/"sloper53"/safe(report.get("name","file"))/"sqlite_tmp.db"
        tmp.parent.mkdir(parents=True,exist_ok=True)
        tmp.write_bytes(data)
        con=sqlite3.connect(str(tmp))
        cur=con.cursor()
        tables=[r[0] for r in cur.execute("select name from sqlite_master where type='table'").fetchall()]
        dump={"tables":{},"schema":[]}
        dump["schema"]=[r for r in cur.execute("select type,name,tbl_name,sql from sqlite_master").fetchall()]
        text_blob=""
        for t in tables[:80]:
            try:
                cols=[r[1] for r in cur.execute(f"pragma table_info({json.dumps(t)})").fetchall()]
            except Exception:
                cols=[]
            try:
                rows=cur.execute(f"select * from {json.dumps(t)} limit 500").fetchall()
            except Exception:
                rows=[]
            dump["tables"][t]={"columns":cols,"rows":rows[:500]}
            text_blob += "\n".join(map(str,rows[:500]))+"\n"
        con.close()
        art=sl53_art(root,report,"sqlite_dump.json",json.dumps(dump,indent=2,ensure_ascii=False,default=str),"sloper53_sqlite_dump",360,"SQLite schema and first rows dump.")
        if art:
            arts.append(art)
            sl53_promote_text(report,text_blob,"SLOPER v53 SQLite dump",art.get("path"),320)
        report.setdefault("next_steps",[]).insert(0,{"priority":96,"step":"Review sqlite_dump.json.","why":"v53 dumped SQLite schema and rows."})
    except Exception as e:
        sl53_trace(report,"SQLite failed",str(e),0)
    return arts
def sl53_office_pdf_text_agent(report, root, data):
    p=Path(report.get("path",""))
    ext=p.suffix.lower()
    arts=[]
    texts=[]
    if ext in [".docx",".xlsx",".pptx",".odt",".ods",".odp"] or data.startswith(b"PK\x03\x04"):
        try:
            import zipfile as _zipfile, io as _io
            with _zipfile.ZipFile(_io.BytesIO(data)) as z:
                for n in z.namelist()[:800]:
                    if n.lower().endswith((".xml",".rels",".txt")):
                        raw=z.read(n)
                        txt=raw[:500000].decode("utf-8","ignore")
                        # Strip XML tags lightly.
                        clean=re.sub(r"<[^>]+>"," ",txt)
                        if clean.strip():
                            texts.append(f"--- {n} ---\n{clean[:200000]}")
        except Exception:
            pass
    if ext==".pdf" or data.startswith(b"%PDF"):
        # Raw PDF text/string fallback; external pdftotext may already exist elsewhere.
        raw=data[:5_000_000].decode("latin1","ignore")
        strings=re.findall(r"\(([^()]{3,300})\)",raw)
        hexstrings=[]
        for hx in re.findall(r"<([0-9A-Fa-f\s]{8,600})>",raw)[:500]:
            try:
                b=bytes.fromhex(re.sub(r"\s+","",hx))
                t=b.decode("utf-8","ignore")
                if t.strip(): hexstrings.append(t)
            except Exception:
                pass
        texts.append("\n".join(strings[:500]+hexstrings[:500]))
    if texts:
        blob="\n".join(texts)
        art=sl53_art(root,report,"document_raw_text_extract.txt",blob[:800000],"sloper53_document_raw_text",330,"Office/PDF raw text extraction fallback.")
        if art:
            arts.append(art)
            sl53_promote_text(report,blob,"SLOPER v53 document text",art.get("path"),310)
    return arts
def sl53_source_deobf_agent(report, root, data):
    p=Path(report.get("path",""))
    ext=p.suffix.lower()
    if ext not in [".py",".js",".ts",".php",".rb",".java",".c",".cpp",".h",".cs",".go",".rs",".txt",".html"]:
        return []
    if len(data)>2_000_000:
        return []
    txt=data.decode("utf-8","ignore")
    if not txt.strip():
        return []
    arts=[]
    findings=[]
    import base64 as _b64
    # String literals and char codes.
    literals=re.findall(r"""['"]([^'"]{4,1000})['"]""",txt)[:1200]
    # Python/JS charcode arrays.
    for arr in re.findall(r"\[([0-9,\s]{15,3000})\]",txt)[:200]:
        nums=[int(x) for x in re.findall(r"\d{1,3}",arr)]
        if nums and all(0<=x<=255 for x in nums):
            s="".join(chr(x) for x in nums)
            if sl43_text_quality(s)>60 or "ctf" in s.lower() or "{" in s:
                findings.append({"method":"charcode_array","text":s[:4000]})
    for lit in literals:
        for candidate in [lit, lit[::-1]]:
            # b64 / hex / rot13-ish simple attempts.
            if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}",candidate):
                for pad in ["","=","==","==="]:
                    try:
                        raw=_b64.urlsafe_b64decode(candidate+pad)
                        s=raw.decode("utf-8","ignore")
                        if sl43_text_quality(s)>60 or "ctf" in s.lower() or "{" in s:
                            findings.append({"method":"base64_literal","literal":lit[:80],"text":s[:4000]})
                    except Exception:
                        pass
            if re.fullmatch(r"[0-9a-fA-F]{8,}",candidate) and len(candidate)%2==0:
                try:
                    s=bytes.fromhex(candidate).decode("utf-8","ignore")
                    if sl43_text_quality(s)>60 or "ctf" in s.lower() or "{" in s:
                        findings.append({"method":"hex_literal","literal":lit[:80],"text":s[:4000]})
                except Exception:
                    pass
    if findings:
        art=sl53_art(root,report,"source_deobf_candidates.json",json.dumps(findings[:200],indent=2,ensure_ascii=False),"sloper53_source_deobf",340,"Source-code literal/charcode/base64/hex deobfuscation candidates.")
        if art:
            arts.append(art)
            for f in findings[:50]:
                sl53_promote_text(report,f.get("text",""),"SLOPER v53 source deobf",art.get("path"),300)
        report.setdefault("next_steps",[]).insert(0,{"priority":96,"step":"Review source_deobf_candidates.json.","why":"v53 decoded source literals, charcode arrays, base64 and hex strings."})
    return arts
def sl53_run_agents(report, root, data):
    arts=[]
    for fn,name in [
        (sl53_zip_password_agent,"ZIP clue password"),
        (sl53_wav_audio_agent,"WAV audio"),
        (sl53_sqlite_agent,"SQLite"),
        (sl53_office_pdf_text_agent,"Document raw text"),
        (sl53_source_deobf_agent,"Source deobf"),
    ]:
        try:
            arts += fn(report,root,data) or []
        except Exception as e:
            sl53_trace(report,name+" failed",str(e),0)
    try: sl_finalize_report(report)
    except Exception: pass
    return arts
_prev_sl_run_agents_v53 = sl_run_agents
def sl_run_agents(report, root, data):
    arts=[]
    try:
        prev=_prev_sl_run_agents_v53(report,root,data)
        if prev: arts += prev
    except Exception as e:
        sl53_trace(report,"previous agents failed",str(e),0)
    try:
        arts += sl53_run_agents(report,root,data) or []
    except Exception as e:
        sl53_trace(report,"v53 agents failed",str(e),0)
    return arts
_prev_project_summary_v53 = project_summary
