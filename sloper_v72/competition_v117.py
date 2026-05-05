"""v117 real-corpus hardening layer.

This layer is intentionally conservative and local-only. It adds fast routes that
showed up in real Cyber Sprint / public CTF-style packs but were not strong
enough in v116:

- task-statement suppression for generated flag candidates;
- time-log anomaly feature extraction;
- JSON tile/artifact-log reconstruction scanned as evidence;
- EXIF/GPS extraction from standalone images and ZIP photo packs;
- extra DNS/HTTP strings from PCAP-like captures;
- operator inventory metadata for URL-only / manual OSINT tasks.
"""
from __future__ import annotations

import datetime as _dt
import io
import json
import os
import re
import struct
import time
import zipfile
from pathlib import Path
from typing import Any

try:
    from PIL import Image, ExifTags
except Exception:  # pragma: no cover
    Image = None
    ExifTags = None

from .competition_v116 import _append_flags, _artifact, _scan, _txt, _printable, _sha

FLAG_FORMAT_HINT_RE = re.compile(r"v[ėe]liav|formatas\s+ctf|ctf_cs\{\.\.\.\}|vietos_pavadinimas|gatves_pavadinimas", re.I)
URL_RE = re.compile(r"https?://[^\s)]+", re.I)


def _record(report: dict[str, Any], root: Path, rel: str, profile: dict[str, Any], manifest: list[dict[str, Any]], rows: list[dict[str, Any]], label: str, payload: bytes | str, note: str, score: int = 990, confidence: str = "medium") -> None:
    raw = payload.encode("utf-8", "ignore") if isinstance(payload, str) else bytes(payload or b"")
    if not raw:
        return
    manifest.append({"label": label, "note": note, "size": len(raw), "sha16": _sha(raw)})
    art_payload: bytes | str = payload
    if isinstance(payload, bytes):
        txt = _printable(payload, 500_000)
        art_payload = txt if txt.strip() else payload[:700_000]
    _artifact(report, root, f"v117_{re.sub(r'[^A-Za-z0-9_.-]+','_',label)}_{_sha(raw)}.txt", art_payload, "v117_evidence", note, score, label, rel)
    # Do not scan JSON manifests/inventory/metafiles as flag text; route names
    # such as "line_deltas_plus32" look like bare tokens and caused false flags.
    if not any(k in label.lower() for k in ["manifest", "inventory", "meta"]):
        rows.extend(_scan(label, payload, profile, rel, boost=score//2, confidence=confidence))


def _ascii_from(vals: list[int], mode: str = "raw") -> str:
    out=[]
    for v in vals:
        if mode == "low":
            v = v & 255
        elif mode.startswith("plus"):
            v += int(mode[4:])
        elif mode.startswith("minus"):
            v -= int(mode[5:])
        out.append(chr(v) if 32 <= v < 127 else ".")
    return "".join(out)


def _bits_to_text(bits: list[int]) -> dict[str, str]:
    out={}
    for inv in (0,1):
        bstr="".join(str((int(b)&1)^inv) for b in bits)
        for off in range(8):
            for rev in (False, True):
                bs=[]
                for i in range(off, len(bstr)-7, 8):
                    chunk=bstr[i:i+8]
                    if rev: chunk=chunk[::-1]
                    bs.append(int(chunk,2))
                if bs:
                    text="".join(chr(x) if 32<=x<127 else "." for x in bs)
                    if sum(c.isalnum() or c in "{}_-." for c in text) >= max(4, len(text)//3):
                        out[f"bits_inv{inv}_off{off}_{'lsb' if rev else 'msb'}"] = text
    return out


def _time_log_routes(text: str) -> list[tuple[str, str]]:
    if not ("Time anomaly" in text or "Time drift" in text):
        return []
    events=[]
    lines=text.splitlines()
    for ln_no,line in enumerate(lines,1):
        if "Time anomaly" not in line and "Time drift" not in line:
            continue
        m=re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:(\d\d))Z\s+(\S+)\s+(\S+)\s+(.*)", line)
        if not m: continue
        try: t=_dt.datetime.fromisoformat(m.group(1))
        except Exception: continue
        events.append({"line_no":ln_no,"t":t,"sec":int(m.group(2)),"module":m.group(3),"level":m.group(4),"msg":m.group(5),"kind":1 if "anomaly" in m.group(5).lower() else 0})
    if len(events) < 4:
        return []
    base=events[0]["t"]
    secs=[int((e["t"]-base).total_seconds()) for e in events]
    deltas=[secs[i]-secs[i-1] for i in range(1,len(secs))]
    line_n=[e["line_no"] for e in events]
    line_d=[line_n[i]-line_n[i-1] for i in range(1,len(line_n))]
    secmin=[e["sec"] for e in events]
    kinds=[e["kind"] for e in events]
    routes={
        "seconds_from_first_low": _ascii_from(secs,"low"),
        "seconds_deltas": _ascii_from(deltas),
        "seconds_deltas_plus32": _ascii_from(deltas,"plus32"),
        "second_of_minute": _ascii_from(secmin),
        "line_numbers_low": _ascii_from(line_n,"low"),
        "line_deltas_plus32": _ascii_from(line_d,"plus32"),
        "module_initials": "".join(str(e["module"])[0] for e in events),
        "kind_sequence": "".join("A" if k else "D" for k in kinds),
    }
    for name, txt in _bits_to_text(kinds).items():
        routes["kind_"+name]=txt
    for module in sorted(set(e["module"] for e in events)):
        bits=[1 if e["module"]==module else 0 for e in events]
        for name, txt in _bits_to_text(bits).items():
            routes[f"module_{module}_{name}"]=txt
    obj={"event_count":len(events),"first_events":[{k:(v.isoformat() if k=='t' else v) for k,v in e.items()} for e in events[:80]],"routes":routes}
    out=[("time_log_manifest", json.dumps(obj, indent=2, ensure_ascii=False))]
    for k,v in routes.items():
        if v and (re.search(r"[A-Za-z0-9_{}]{5,}", v) or any(x in v.lower() for x in ["ctf","flag","time","drift","anomaly","clock","secret"])):
            out.append(("time_log_"+k, v))
    return out[:80]


def _artifact_log_routes(text: str) -> list[tuple[str, str]]:
    if '"x"' not in text or '"rows"' not in text:
        return []
    entries=[]
    for line in text.splitlines():
        try:
            o=json.loads(line)
        except Exception:
            continue
        if isinstance(o,dict) and "x" in o and "y" in o and isinstance(o.get("rows"),list):
            entries.append(o)
    if not entries:
        return []
    allowed=set(" $/\\_|{}abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-+.:;[]()#*=o")
    valid=[e for e in entries if all(all(ch in allowed for ch in str(r)) for r in e.get("rows",[]))]
    use=valid or entries
    maxx=max(int(e.get("x",0))+max([len(str(r)) for r in e.get("rows",[""])]+[0]) for e in use)
    maxy=max(int(e.get("y",0))+len(e.get("rows",[])) for e in use)
    canvas=[[" "]*maxx for _ in range(maxy)]
    for e in use:
        for dy,row in enumerate(e.get("rows",[])):
            for dx,ch in enumerate(str(row)):
                if ch!=" ":
                    y=int(e.get("y",0))+dy; x=int(e.get("x",0))+dx
                    if 0<=y<maxy and 0<=x<maxx: canvas[y][x]=ch
    art="\n".join("".join(r).rstrip() for r in canvas)
    return [("artifact_log_reconstructed_ascii", art), ("artifact_log_meta", json.dumps({"entries":len(entries),"valid":len(valid),"width":maxx,"height":maxy}, indent=2))]


def _gps_to_decimal(vals: Any, ref: str) -> float | None:
    try:
        def f(x):
            return float(x[0]) / float(x[1]) if isinstance(x, tuple) else float(x)
        deg=f(vals[0]); minute=f(vals[1]); sec=f(vals[2])
        dec=deg + minute/60 + sec/3600
        if ref in ("S","W"): dec=-dec
        return dec
    except Exception:
        return None


def _image_exif_routes(raw: bytes, name: str = "image") -> list[tuple[str, str]]:
    if Image is None:
        return []
    try:
        im=Image.open(io.BytesIO(raw))
        exif=im.getexif()
    except Exception:
        return []
    if not exif:
        return []
    tagmap={v:k for k,v in getattr(ExifTags,"TAGS",{}).items()}
    gps_tags=getattr(ExifTags,"GPSTAGS",{}) if ExifTags else {}
    rows={"name":name,"format":getattr(im,"format",None),"size":getattr(im,"size",None),"tags":{}}
    gps_info={}
    for k,v in exif.items():
        label=ExifTags.TAGS.get(k,k) if ExifTags else k
        if label == "GPSInfo":
            for gk,gv in dict(v).items():
                gps_info[gps_tags.get(gk,gk)] = gv
        else:
            if isinstance(v, bytes):
                try: v=v.decode("utf-8","ignore")
                except Exception: v=repr(v[:80])
            rows["tags"][str(label)] = str(v)[:500]
    if gps_info:
        rows["gps"]={k:str(v) for k,v in gps_info.items()}
        lat=_gps_to_decimal(gps_info.get("GPSLatitude"), gps_info.get("GPSLatitudeRef","N"))
        lon=_gps_to_decimal(gps_info.get("GPSLongitude"), gps_info.get("GPSLongitudeRef","E"))
        if lat is not None and lon is not None:
            rows["gps_decimal"]={"lat":lat,"lon":lon,"maps_hint":f"{lat:.6f},{lon:.6f}"}
    text=json.dumps(rows, indent=2, ensure_ascii=False)
    flat="\n".join([text] + [str(x) for x in rows.get("tags",{}).values()])
    return [("image_exif_json", text), ("image_exif_flat", flat)]


def _zip_image_exif_routes(raw: bytes) -> list[tuple[str, str]]:
    out=[]
    try:
        zf=zipfile.ZipFile(io.BytesIO(raw))
    except Exception:
        return []
    with zf:
        for info in zf.infolist()[:80]:
            if info.is_dir() or info.file_size > 8_000_000:
                continue
            if Path(info.filename).suffix.lower() not in {".jpg",".jpeg",".png",".tif",".tiff",".webp"}:
                continue
            try: child=zf.read(info)
            except Exception: continue
            for label,text in _image_exif_routes(child, info.filename):
                out.append((f"zip_{Path(info.filename).name}_{label}", text))
    return out[:80]


def _pcap_extra_text(raw: bytes) -> list[tuple[str, str]]:
    txt=_printable(raw, 2_000_000)
    outs=[]
    if txt:
        interesting=[]
        for line in txt.splitlines():
            low=line.lower()
            if any(k in low for k in ["host:","get ","post ","http/", "cookie", "authorization", "token", "flag", "ctf", "secret", "password"]):
                interesting.append(line)
        if interesting:
            outs.append(("pcap_http_interesting_lines", "\n".join(interesting[:2000])))
        domains=sorted(set(re.findall(r"(?i)\b[a-z0-9][a-z0-9.-]{2,}\.(?:lt|com|net|org|dev|io|local)\b", txt)))
        if domains:
            outs.append(("pcap_domain_candidates", "\n".join(domains[:2000])))
    return outs


def _inventory_routes(text: str, rel: str) -> list[tuple[str, str]]:
    if not text.strip():
        return []
    urls=URL_RE.findall(text)
    if urls or FLAG_FORMAT_HINT_RE.search(text):
        obj={"file":rel,"urls":urls,"looks_like_task_statement":bool(FLAG_FORMAT_HINT_RE.search(text)),"url_only_manual":bool(urls and len(text)<2000)}
        return [("challenge_inventory", json.dumps(obj, indent=2, ensure_ascii=False))]
    return []


def apply(mod) -> None:
    old_analyze=getattr(mod,"analyze_file",None)
    def analyze_file(pid, path, root, i=1, total=1):
        report=old_analyze(pid,path,root,i,total) if old_analyze else {"flags":[],"artifacts":[]}
        if not isinstance(report,dict): report={"flags":[],"artifacts":[],"error":"previous analyzer returned non-dict"}
        p=Path(path); r=Path(root)
        try: raw=p.read_bytes()
        except Exception: raw=b""
        try: rel=str(p.relative_to(r))
        except Exception: rel=p.name
        try:
            profile=mod.sl111_read_settings() if hasattr(mod,"sl111_read_settings") else {}
        except Exception:
            profile={}
        rows=[]; manifest=[]
        text=_txt(raw, 1_500_000)
        for label,payload in _inventory_routes(text, rel):
            _record(report,r,rel,profile,manifest,rows,label,payload,"v117 challenge/task inventory",650,"low")
        for label,payload in _time_log_routes(text):
            _record(report,r,rel,profile,manifest,rows,label,payload,"v117 time-log anomaly/covert-channel routes",980,"medium")
        for label,payload in _artifact_log_routes(text):
            _record(report,r,rel,profile,manifest,rows,label,payload,"v117 artifact-log reconstruction",1180,"high")
        suffix=p.suffix.lower()
        if suffix in {".jpg",".jpeg",".png",".tif",".tiff",".webp"}:
            for label,payload in _image_exif_routes(raw,p.name):
                _record(report,r,rel,profile,manifest,rows,label,payload,"v117 image EXIF/GPS metadata extraction",900,"medium")
        if suffix == ".zip" or raw.startswith(b"PK\x03\x04"):
            for label,payload in _zip_image_exif_routes(raw):
                _record(report,r,rel,profile,manifest,rows,label,payload,"v117 ZIP photo EXIF/GPS extraction",920,"medium")
        if suffix in {".pcap",".pcapng"} or raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4") or raw.startswith(b"\x0a\x0d\x0d\x0a"):
            for label,payload in _pcap_extra_text(raw):
                _record(report,r,rel,profile,manifest,rows,label,payload,"v117 packet text/domain/HTTP extraction",980,"medium")
        if rows:
            _append_flags(report, rows, rel)
        if manifest:
            _artifact(report,r,"v117_real_corpus_manifest.json",json.dumps(manifest,indent=2,ensure_ascii=False),"v117_manifest","v117 real-corpus route manifest",1170,"v117_real_corpus",rel)
        report["v117_competition"]={"enabled":True,"version":"v117-real-corpus","findings":len(rows),"manifest_items":len(manifest),"updated":int(time.time())}
        return report
    mod.analyze_file=analyze_file
    try:
        @mod.app.get("/api/v117_status")
        def v117_status():
            return {"ok":True,"version":"v117-real-corpus","routes":["time-log","artifact-log","exif-gps","zip-photo-exif","pcap-http-dns","inventory"]}
    except Exception:
        pass
