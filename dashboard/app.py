"""Streamlit viewer for a saved review run.

Run:  streamlit run dashboard/app.py
Reads review-output.json (list of finding dicts) from the repo root
when present; otherwise shows an upload prompt.
"""

from __future__ import annotations

import json
import os

import streamlit as st

st.set_page_config(page_title="AI Code Reviewer", page_icon="🔍")
st.title("AI Code Reviewer — Findings")

findings: list[dict] = []
default_path = os.path.join(os.path.dirname(__file__), "..", "review-output.json")
if os.path.isfile(default_path):
    with open(default_path) as fh:
        findings = json.load(fh)
else:
    uploaded = st.file_uploader("Upload review-output.json", type="json")
    if uploaded is not None:
        findings = json.load(uploaded)

if not findings:
    st.info("No findings loaded yet. Run a review and save its JSON output.")
else:
    cols = st.columns(3)
    for col, sev in zip(cols, ["critical", "warning", "info"]):
        col.metric(sev.title(), sum(1 for f in findings if f.get("severity") == sev))
    st.dataframe(
        [
            {
                "File": f.get("file", ""),
                "Line": f.get("line_number", ""),
                "Severity": f.get("severity", ""),
                "Category": f.get("category", ""),
                "Confidence": f.get("confidence", ""),
                "Issue": f.get("issue_description", ""),
            }
            for f in findings
        ],
        use_container_width=True,
    )
