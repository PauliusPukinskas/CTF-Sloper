def test_v123_decoy_ranked_below_decoded_real_flag():
    from sloper_v72.evidence_v123 import apply

    class M:
        pass

    m = M()

    def old_summary(reports, meta):
        return {
            "flags": [
                {
                    "flag": "ctf_cs{fake_example_ignore_me}",
                    "preferred_flag": "ctf_cs{fake_example_ignore_me}",
                    "score": 2840,
                    "v117_score": 3020,
                    "source": "v117_strict_artifact_rescue",
                },
                {
                    "flag": "ctf_cs{real_after_decoy_20}",
                    "preferred_flag": "ctf_cs{real_after_decoy_20}",
                    "score": 990,
                    "v117_score": 1570,
                    "source": "input->base64->gzip",
                    "why": "strict wrapper; matches selected flag prefix; transform evidence; multiple evidence stages",
                },
            ],
            "artifacts": [],
        }

    m.project_summary = old_summary
    apply(m)
    summary = m.project_summary([], {})
    assert summary["flags"][0]["flag"] == "ctf_cs{real_after_decoy_20}"
    assert "decoy_or_example_body" in summary["flags"][1]["v123_risk"]
