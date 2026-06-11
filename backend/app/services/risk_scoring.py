from app.models.scan import Severity

BANDIT_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def cvss_to_severity(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def bandit_to_severity(level: str) -> Severity:
    return BANDIT_SEVERITY_MAP.get(level.upper(), Severity.MEDIUM)


def semgrep_to_severity(level: str) -> Severity:
    return SEMGREP_SEVERITY_MAP.get(level.upper(), Severity.MEDIUM)
