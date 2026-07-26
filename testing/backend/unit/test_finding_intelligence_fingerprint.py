"""
Unit tests for _fingerprint_score in backend/secuscan/finding_intelligence.py.

Run with:
    python3 -m pytest testing/backend/unit/test_finding_intelligence_fingerprint.py -v --noconftest
"""

from backend.secuscan import finding_intelligence as fi


class TestFingerprintScore:
    def test_returns_tuple_of_float_and_str(self):
        result = fi._fingerprint_score({"metadata": {"match_strength": "exact"}})
        assert isinstance(result, tuple)
        assert len(result) == 2
        score, reason = result
        assert isinstance(score, float)
        assert isinstance(reason, str)

    def test_deterministic_for_same_input(self):
        finding = {"metadata": {"match_strength": "strong_fuzzy"}, "validated": False}
        first = fi._fingerprint_score(finding)
        second = fi._fingerprint_score(dict(finding))
        assert first == second

    def test_validated_true_without_metadata_scores_as_validated(self):
        score, reason = fi._fingerprint_score({"validated": True})
        assert reason == "validated"
        assert score == 1.0

    def test_unvalidated_without_metadata_scores_as_none(self):
        score, reason = fi._fingerprint_score({"validated": False})
        assert reason == "none"
        assert score == 0.25

    def test_explicit_match_strength_takes_priority_over_validated_flag(self):
        # A finding can be validated=True but still carry a weaker explicit
        # match_strength in metadata — the explicit value must win.
        score, reason = fi._fingerprint_score(
            {"validated": True, "metadata": {"match_strength": "fuzzy"}}
        )
        assert reason == "fuzzy"
        assert score == 0.7

    def test_cpe_match_strength_used_when_match_strength_absent(self):
        score, reason = fi._fingerprint_score(
            {"metadata": {"cpe_match_strength": "family"}}
        )
        assert reason == "family"
        assert score == 0.45

    def test_match_strength_takes_priority_over_cpe_match_strength(self):
        score, reason = fi._fingerprint_score(
            {"metadata": {"match_strength": "exact", "cpe_match_strength": "family"}}
        )
        assert reason == "exact"
        assert score == 0.95

    def test_match_strength_is_case_insensitive(self):
        score, reason = fi._fingerprint_score({"metadata": {"match_strength": "EXACT"}})
        assert reason == "exact"
        assert score == 0.95

    def test_unknown_match_strength_scores_zero(self):
        score, reason = fi._fingerprint_score({"metadata": {"match_strength": "made_up_value"}})
        assert score == 0.0
        assert reason == "made_up_value"

    def test_missing_metadata_field_handled_gracefully(self):
        # No "metadata" key at all — should not raise.
        score, reason = fi._fingerprint_score({})
        assert reason == "none"
        assert score == 0.25

    def test_none_metadata_handled_gracefully(self):
        score, reason = fi._fingerprint_score({"metadata": None})
        assert reason == "none"
        assert score == 0.25

    def test_non_dict_metadata_handled_gracefully(self):
        # metadata as a non-dict type must not raise (isinstance guard in source).
        score, reason = fi._fingerprint_score({"metadata": "not-a-dict"})
        assert reason == "none"
        assert score == 0.25

    def test_score_unaffected_by_severity(self):
        base = {"metadata": {"match_strength": "exact"}, "severity": "critical"}
        varied = {"metadata": {"match_strength": "exact"}, "severity": "info"}
        assert fi._fingerprint_score(base) == fi._fingerprint_score(varied)

    def test_score_unaffected_by_asset_refs(self):
        base = {"metadata": {"match_strength": "exact"}, "asset_refs": ["host-a"]}
        varied = {"metadata": {"match_strength": "exact"}, "asset_refs": ["host-b", "host-c"]}
        assert fi._fingerprint_score(base) == fi._fingerprint_score(varied)

    def test_score_unaffected_by_target(self):
        base = {"metadata": {"match_strength": "exact"}, "target": "example.com"}
        varied = {"metadata": {"match_strength": "exact"}, "target": "other.example.org"}
        assert fi._fingerprint_score(base) == fi._fingerprint_score(varied)

    def test_different_metadata_sources_produce_different_scores(self):
        # "Source" here is metadata carrying a different signal per scanner —
        # e.g. one plugin reports an exact CPE match, another only a fuzzy one.
        exact_source = fi._fingerprint_score({"metadata": {"match_strength": "exact"}})
        fuzzy_source = fi._fingerprint_score({"metadata": {"match_strength": "fuzzy"}})
        assert exact_source != fuzzy_source