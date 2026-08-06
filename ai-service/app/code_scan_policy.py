from __future__ import annotations

import uuid

from .code_scan_common import clean_text
from .code_scan_models import (
    CodeAssessmentVerdict,
    CodeFindingAssessment,
    CodeScanAnalysis,
    CodeScanFinding,
    CodeScanRequest,
    CodeScanVerdict,
    CodeSeverity,
)

RANK = {
    CodeSeverity.INFO: 0,
    CodeSeverity.LOW: 1,
    CodeSeverity.MEDIUM: 2,
    CodeSeverity.HIGH: 3,
    CodeSeverity.CRITICAL: 4,
}
_WEIGHT = {
    CodeSeverity.INFO: 5,
    CodeSeverity.LOW: 20,
    CodeSeverity.MEDIUM: 45,
    CodeSeverity.HIGH: 70,
    CodeSeverity.CRITICAL: 90,
}
_SEVERITIES = list(CodeSeverity)
_EXAMPLE_PARTS = {"test", "tests", "fixture", "fixtures", "example", "examples", "demo", "samples"}


def remediation(finding: CodeScanFinding) -> str:
    tags = set(finding.tags)
    if "secret" in tags:
        return "ย้าย secret ไป secret manager จากนั้น revoke และ rotate ค่าเดิม"
    if tags & {"command-injection", "rce"}:
        return "หลีกเลี่ยง shell ส่ง argument แยกค่า ใช้ allowlist และห้าม input กำหนด executable"
    if "deserialization" in tags:
        return "ใช้ข้อมูลที่ไม่สร้าง object อัตโนมัติและตรวจ schema ก่อนประมวลผล"
    if "tls" in tags:
        return "ห้ามปิด TLS verification และใช้ CA หรือ pinning ตามนโยบาย"
    if "sql-injection" in tags:
        return "ใช้ prepared statement หรือ parameterized query โดยไม่ต่อ string จาก input"
    if "xss" in tags:
        return "ใช้ context-aware output encoding และหลีกเลี่ยง HTML execution sink"
    return "ตรวจ data flow ลดสิทธิ์ของ sink และเพิ่ม regression test"


def build_fallback(request: CodeScanRequest) -> CodeScanAnalysis:
    same_position: dict[tuple[str, int], set[str]] = {}
    for finding in request.findings:
        same_position.setdefault((finding.path, finding.line), set()).add(finding.rule_id)

    assessments: list[CodeFindingAssessment] = []
    for finding in request.findings:
        severity = finding.severity
        confidence = finding.confidence
        verdict = (
            CodeAssessmentVerdict.CONFIRMED
            if confidence >= 0.90
            else CodeAssessmentVerdict.LIKELY
            if confidence >= 0.70
            else CodeAssessmentVerdict.NEEDS_CONTEXT
        )
        reasons = [f"กฎ {finding.rule_id} พบรูปแบบที่สอดคล้องกับ {finding.title}"]
        path_parts = {part.lower() for part in finding.path.replace("\\", "/").split("/")}
        if path_parts & _EXAMPLE_PARTS:
            severity = _SEVERITIES[max(0, RANK[severity] - 1)]
            confidence = min(confidence, 0.65)
            verdict = CodeAssessmentVerdict.NEEDS_CONTEXT
            reasons.append("ไฟล์อยู่ใน test/example จึงต้องยืนยันว่าใช้ใน production")
        if finding.rule_id.endswith("DANGEROUS_EXEC") and any(
            rule.endswith("COMMAND_INJECTION") for rule in same_position[(finding.path, finding.line)]
        ):
            severity = min(severity, CodeSeverity.MEDIUM, key=lambda item: RANK[item])
            reasons.append("เป็นสัญญาณซ้ำกับ command injection ที่ตำแหน่งเดียวกัน")
        if request.privacy_mode == "metadata" or not finding.snippet:
            verdict = CodeAssessmentVerdict.NEEDS_CONTEXT
            confidence = min(confidence, 0.68)
            reasons.append("ไม่มี snippet สำหรับตรวจ data flow")
        assessments.append(
            CodeFindingAssessment(
                finding_id=finding.finding_id,
                verdict=verdict,
                adjusted_severity=severity,
                confidence=max(0.05, min(confidence, 0.99)),
                rationale_th="; ".join(reasons),
                remediation=remediation(finding),
                evidence_refs=[finding.finding_id],
            )
        )

    risk = risk_score(assessments)
    verdict = scan_verdict(risk, bool(assessments))
    critical = sum(item.adjusted_severity == CodeSeverity.CRITICAL for item in assessments)
    high = sum(item.adjusted_severity == CodeSeverity.HIGH for item in assessments)
    summary = (
        f"NTShield AV สแกน {request.summary.files_scanned} ไฟล์ใน {request.project.name} "
        "และไม่พบ pattern ที่เข้าเกณฑ์ ทั้งนี้ไม่ใช่หลักฐานว่าโค้ดปลอดภัยทั้งหมด"
        if not assessments
        else f"โครงการ {request.project.name} มี {len(assessments)} findings: "
        f"Critical {critical}, High {high}; ความเสี่ยง {risk}/100 ระดับ {verdict.value}"
    )
    warnings = [clean_text(item, 500) for item in request.errors[:20]]
    if request.privacy_mode == "metadata" and assessments:
        warnings.append("รายงานเป็น metadata-only จึงต้องตรวจ source ในเครื่องก่อนตัดสิน")
    return CodeScanAnalysis(
        scan_id=request.scan_id,
        analysis_id="caa-" + uuid.uuid4().hex,
        verdict=verdict,
        risk_score=risk,
        confidence=overall_confidence(assessments),
        summary_th=summary,
        model="deterministic-code-review-v1",
        llm_used=False,
        deterministic_fallback=True,
        assessments=assessments,
        attack_surface=attack_surface(request),
        priority_actions=priority_actions(request, assessments),
        warnings=list(dict.fromkeys(warnings))[:50],
        input_findings=len(request.findings),
    )


def risk_score(assessments: list[CodeFindingAssessment]) -> int:
    scored = [
        round(_WEIGHT[item.adjusted_severity] * (0.70 + 0.30 * item.confidence))
        for item in assessments
        if item.verdict != CodeAssessmentVerdict.FALSE_POSITIVE
    ]
    if not assessments:
        return 0
    if not scored:
        return 5
    high = sum(
        item.adjusted_severity in {CodeSeverity.HIGH, CodeSeverity.CRITICAL}
        and item.verdict != CodeAssessmentVerdict.FALSE_POSITIVE
        for item in assessments
    )
    return min(100, max(scored) + min(12, max(0, high - 1) * 2))


def risk_floor(assessments: list[CodeFindingAssessment]) -> int:
    floor = 0
    for item in assessments:
        if item.verdict == CodeAssessmentVerdict.FALSE_POSITIVE:
            continue
        if item.adjusted_severity == CodeSeverity.CRITICAL:
            floor = max(floor, 85 if item.verdict == CodeAssessmentVerdict.CONFIRMED else 75)
        elif item.adjusted_severity == CodeSeverity.HIGH:
            floor = max(floor, 65 if item.verdict == CodeAssessmentVerdict.CONFIRMED else 55)
        elif item.adjusted_severity == CodeSeverity.MEDIUM:
            floor = max(floor, 35)
    return floor


def scan_verdict(score: int, has_findings: bool) -> CodeScanVerdict:
    if not has_findings:
        return CodeScanVerdict.CLEAN
    if score >= 85:
        return CodeScanVerdict.CRITICAL
    if score >= 65:
        return CodeScanVerdict.HIGH
    if score >= 40:
        return CodeScanVerdict.MEDIUM
    if score >= 15:
        return CodeScanVerdict.LOW
    return CodeScanVerdict.NEEDS_REVIEW


def overall_confidence(assessments: list[CodeFindingAssessment]) -> float:
    if not assessments:
        return 0.98
    top = sorted(
        assessments,
        key=lambda item: (RANK[item.adjusted_severity], item.confidence),
        reverse=True,
    )[:10]
    return round(sum(item.confidence for item in top) / len(top), 3)


def attack_surface(request: CodeScanRequest) -> list[str]:
    values: list[str] = []
    for finding in request.findings:
        for item in [finding.language, *finding.tags]:
            value = clean_text(item, 100)
            if value and value not in values:
                values.append(value)
    return values[:50]


def priority_actions(
    request: CodeScanRequest,
    assessments: list[CodeFindingAssessment],
) -> list[str]:
    active = [
        (finding, assessment)
        for finding, assessment in zip(request.findings, assessments, strict=True)
        if assessment.verdict != CodeAssessmentVerdict.FALSE_POSITIVE
    ]
    actions: list[str] = []
    if any(item.adjusted_severity == CodeSeverity.CRITICAL for _, item in active):
        actions.append("หยุด deploy จนกว่า Critical findings จะผ่านการตรวจสอบ")
    tags = {tag for finding, _ in active for tag in finding.tags}
    checks = (
        ("secret", "เพิกถอนและหมุน credential พร้อมตรวจประวัติ Git และระบบปลายทาง"),
        ("command-injection", "เลิกประกอบ command จาก input และส่ง argument แยกค่าโดยไม่ผ่าน shell"),
        ("deserialization", "เลิก deserialize object ภายนอกหรือบังคับ schema และ allowlist"),
        ("tls", "เปิด certificate verification และใช้ trust store ตามนโยบาย"),
        ("sql-injection", "เปลี่ยนเป็น parameterized query และตรวจชนิด input"),
    )
    actions.extend(action for tag, action in checks if tag in tags)
    actions.append("ยืนยัน reachable path, authentication boundary และ regression test ก่อนปิด finding")
    return list(dict.fromkeys(actions))[:30]


def clean_list(values: list[str], count: int, limit: int) -> list[str]:
    result: list[str] = []
    for value in values[:count]:
        item = clean_text(value, limit)
        if item and item not in result:
            result.append(item)
    return result
