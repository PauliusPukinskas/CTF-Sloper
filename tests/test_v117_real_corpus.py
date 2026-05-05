import json
import tempfile
from pathlib import Path


def test_v117_time_log_routes_exposes_artifacts():
    from sloper_v72.competition_v117 import _time_log_routes
    lines=[]
    t=0
    kinds=["Time drift detected","Time anomaly"]*8
    for i,k in enumerate(kinds):
        lines.append(f"2025-03-14T10:00:{(i*3)%60:02d}Z CORE WARN {k}")
    routes=dict(_time_log_routes("\n".join(lines)))
    assert "time_log_manifest" in routes
    assert any(k.startswith("time_log_kind_bits") or k.startswith("time_log_module") for k in routes) or any(k.startswith("kind_") for k in routes)


def test_v117_artifact_log_reconstructs_canvas():
    from sloper_v72.competition_v117 import _artifact_log_routes
    txt='\n'.join([
        json.dumps({"x":0,"y":0,"rows":["ctf_cs{"]}),
        json.dumps({"x":7,"y":0,"rows":["tile_ok}"]}),
    ])
    routes=dict(_artifact_log_routes(txt))
    assert "artifact_log_reconstructed_ascii" in routes
    assert "ctf_cs{tile_ok}" in routes["artifact_log_reconstructed_ascii"]


def test_v117_evidence_demotes_timestamp_and_promotes_hash():
    from sloper_v72.evidence_v117 import apply
    class M: pass
    m=M()
    def old_summary(reports, meta):
        return {"flags":[
            {"flag":"ctf_cs{2025-01-10T16:45:00Z}","score":3000,"source":"docProps/core.xml"},
            {"flag":"ctf_cs{"+"a"*64+"}","score":1200,"source":"cardan_sha256"},
        ],"artifacts":[]}
    m.project_summary=old_summary
    apply(m)
    s=m.project_summary([],{})
    assert s["flags"][0]["flag"] == "ctf_cs{"+"a"*64+"}"
    assert "metadata_timestamp" in s["flags"][1]["v117_risk"]
