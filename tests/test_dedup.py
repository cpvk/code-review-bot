from src.dedup import deduplicate_findings, merge_findings


def _f(line, conf, cat="security", file="a.py"):
    return {"file": file, "line_number": line, "category": cat, "confidence": conf}


def test_dedup_keeps_highest_confidence_per_file_line_category():
    out = deduplicate_findings([_f(3, 0.4), _f(3, 0.9), _f(3, 0.7, cat="bug")])
    assert len(out) == 2
    assert max(f["confidence"] for f in out if f["category"] == "security") == 0.9


def test_merge_llm_wins_and_tags_source():
    out = merge_findings([_f(5, 0.5)], [_f(5, 0.5), _f(9, 0.3)])
    by_line = {f["line_number"]: f for f in out}
    assert by_line[5]["source"] == "llm" and len(out) == 2
