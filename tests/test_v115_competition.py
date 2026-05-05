from pathlib import Path
import io, zipfile, struct

from PIL import Image

from sloper_v72.competition_v115 import _pdf_extract, _jpeg_gif_metadata, _pcap_payloads, _deep_image_lsb, _zip_dynamic
from sloper_v72.evidence_v115 import enrich_summary


def test_v115_pdf_extracts_flate_stream_flag():
    import zlib
    payload = b"BT (ctf_cs{pdf_stream_v115}) Tj ET"
    comp = zlib.compress(payload)
    raw = b"%PDF-1.4\n1 0 obj\n<</Filter /FlateDecode>>\nstream\n" + comp + b"\nendstream\nendobj\n"
    items = dict(_pdf_extract(raw))
    assert any(b"ctf_cs{pdf_stream_v115}" in v for v in items.values())


def test_v115_jpeg_comment_flag():
    raw = b"\xff\xd8\xff\xfe\x00\x1bctf_cs{jpeg_comment_v115}\xff\xd9"
    items = dict(_jpeg_gif_metadata(raw))
    assert any(b"ctf_cs{jpeg_comment_v115}" in v for v in items.values())


def test_v115_pcap_payload_strings():
    pkt = b"\x00" * 42 + b"GET /?q=ctf_cs{pcap_payload_v115} HTTP/1.1\r\n\r\n"
    hdr = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 1, 0, len(pkt), len(pkt)) + pkt
    items = dict(_pcap_payloads(hdr + rec))
    assert any(b"ctf_cs{pcap_payload_v115}" in v for v in items.values())


def test_v115_deep_image_lsb_rgb(tmp_path: Path):
    msg = b"ctf_cs{image_lsb_v115}"
    bits = []
    for b in msg:
        bits.extend((b >> i) & 1 for i in range(7, -1, -1))
    pixels = []
    it = iter(bits)
    for _ in range(100):
        vals = []
        for _c in range(3):
            try: bit = next(it)
            except StopIteration: bit = 0
            vals.append(254 | bit)
        pixels.append(tuple(vals + [255]))
    im = Image.new("RGBA", (10, 10))
    im.putdata(pixels)
    p = tmp_path / "lsb.png"
    im.save(p)
    items = dict(_deep_image_lsb(p, 0.0))
    assert any(b"ctf_cs{image_lsb_v115}" in v for v in items.values())


def test_v115_dynamic_zip_password_from_filename():
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("note.txt", "ctf_cs{zip_dynamic_v115}")
    items = _zip_dynamic(bio.getvalue(), "slaptas.zip")
    assert any(b"ctf_cs{zip_dynamic_v115}" in data for _name, data, _pwd in items)


def test_v115_summary_buckets_best_flag():
    summary = enrich_summary({
        "flags": [
            {"flag": "ctf_cs{fake_example_flag}", "confidence": 90, "risk": 10, "score": 900, "source": "example"},
            {"flag": "ctf_cs{real_v115_best}", "confidence": 86, "risk": 12, "score": 1200, "source": "v115_pdf_stream"},
        ],
        "artifacts": [{"kind": "v115_manifest", "name": "v115_competition_manifest.json"}],
    })
    assert summary["v115_triage"]["best_flag"] == "ctf_cs{real_v115_best}"
    assert summary["v115_triage"]["trusted"] >= 1
