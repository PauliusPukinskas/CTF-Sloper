# CTF Sloper v115 — Broad Extractor + Live Triage Upgrade

v115 is focused on live-competition reliability rather than cosmetic UI changes.
It layers more bounded local extractors on top of v114 and improves operator triage.

## New extraction coverage

- Deep image LSB extraction across RGB/BGR/RGBA/ARGB/individual channels, bit 0/1, normal and reversed pixel order.
- PDF stream extraction, including `/FlateDecode` streams, literal strings, and hex strings.
- JPEG comment/APP marker extraction and GIF comment/application extension extraction.
- Classic PCAP parser that extracts packet payloads and printable packet strings without external tools.
- Dynamic ZIP password retries using local strings, filename tokens, and common CTF/Lithuanian words.
- Token rescue for `data:` URIs, base64/base64url, base85/ascii85, quoted-printable, and uuencoded documents.
- Per-file v115 operator playbook artifacts explaining which extractors fired and what to inspect manually.

## New triage model

`evidence_v115.py` adds:

- trusted / promising / manual-review buckets;
- source coverage counts;
- priority artifact queue;
- best flag source + best score;
- fake/example/dummy flag penalty.

## Safety and runtime limits

v115 stays local-only and does not execute uploaded challenge binaries.  Extractors are bounded by:

- `SLOPER_V115_FILE_BUDGET_MS` default `3500` ms per file;
- `SLOPER_V115_MAX_LSB_BYTES` default `900000` bytes;
- `SLOPER_V115_MAX_PCAP_PACKETS` default `400` packets;
- `SLOPER_V115_MAX_ZIP_PASSWORDS` default `120` candidates.

## Recommended benchmark command

```bash
python3 scripts/benchmark_challenge_pack.py /path/to/challenges \
  --flag-format ctf_cs \
  --attack-preset deep \
  --difficulty multi_step \
  --max-depth 6 \
  --out docs/CHALLENGE_PACK_BENCHMARK_v115.json \
  --html-out docs/CHALLENGE_PACK_BENCHMARK_v115.html
```
