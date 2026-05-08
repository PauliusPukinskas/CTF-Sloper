# CTF SLOPER FINAL Changelog

## Backend reliability guard update

- Added `sloper/backend_guard.py` as a late backend-only runtime guard. It keeps
  the existing solver stack intact while hardening uploads, raw file serving,
  project id validation, log tailing, report writes, archive extraction caps,
  custom regex handling, and accidental execution of uploaded binaries.
- Added streaming upload handling so files are size-checked while being written
  instead of being read fully into RAM first.
- Added per-project analysis locking so repeated start requests do not launch
  duplicate jobs against the same report.
- Blocked automatic ELF/PE execution and tracing by default; static binary
  artifacts remain available for normal CTF reversing workflows.
- Disabled unsafe marshal-based `.pyc` loading and replaced it with safe string
  extraction evidence.
- Synchronized older v114-v117 triage headlines with the final clean ranking
  gate, so stale ROT/route noise cannot remain the displayed "best flag" after a
  real decoded/extracted artifact has been ranked first.
- Added `scripts/backend_guard_smoke.py` covering path containment, upload
  health, custom regex sanitation, raw artifact access, invalid project ids,
  `events.log` tailing, binary execution blocking, and ranking/triage sync.

- Added `sloper_v72/final_engine.py` as a final modular wrapper over v104.
- Added final text, archive, PCAP and project multi-file workflows.
- Added recursive onion peeling, safe archive-child guards, final image color
  review artifacts and a fast bounded binary/reversing route.
- Fixed a binary workflow hang on ELF-style reversing tasks while preserving
  stack-array transform evidence for wrapped flag promotion.
- Promoted high-signal artifact bodies when the statement says to wrap the
  extracted text as `ctf_cs{...}`.
- Added final workflow map, open-first queue and unconfirmed strict-flag bucket.
- Preserved all fragments, bare braces, leetspeak and alternate-format evidence
  for human review instead of hiding it.
- Cleaned the visible workspace to 8 tabs: Brief, Open First, Flags, Artifacts,
  Transforms, Files, Health, Logs.
- Removed the visible Global AI navigation/workflow.
- Kept Stop Project, runtime display, artifact open/download/copy, file
  download and agent health views.
- Updated README and startup labels for the FINAL build.

## v114

- Added recursive payload frontier with bounded breadth/depth and transform-chain provenance.
- Added Office ZIP text normalization, SQLite text extraction, PNG chunk extraction, WAV LSB extraction, XOR rescue, and image bit-plane preview artifacts.
- Added v114 evidence triage summary for best flag, confidence buckets, artifact-kind counts, and operator hints.
- Expanded synthetic benchmark to cover DOCX XML, SQLite, PNG zTXt, WAV LSB, nested zlib/base64 frontier, and XOR rescue.
- Challenge-pack benchmark now emits HTML as well as JSON.
