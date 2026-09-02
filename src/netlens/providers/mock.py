from netlens.providers.base import ProviderResult
from netlens.schemas import ObservedIssue, ReportContent


class MockProvider:
    def generate(self, context: dict) -> ProviderResult:
        findings = context["findings"]
        content = ReportContent(
            summary=f"The capture has {len(findings)} deterministic findings.",
            observed_issues=[
                ObservedIssue(finding_ids=[f["id"]], explanation=f["observation"]) for f in findings
            ],
            hypotheses=[],
            next_checks=["Compare a capture from the other endpoint and a longer time window."],
            evidence_limitations=[
                "Capture visibility is incomplete; missing observations do not prove packet loss.",
                "Encrypted application payloads are not inspected.",
            ],
        )
        return ProviderResult(content, "deterministic-v1")
