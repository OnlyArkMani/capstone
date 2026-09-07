import docx
from docx.shared import Pt, Inches
import os

def create_report():
    doc = docx.Document()
    
    # Title
    title = doc.add_heading('Technical Audit Report: Hallucinations in AI-Driven Cybersecurity Systems', 0)
    
    # Exec Summary
    doc.add_heading('1. Executive Summary', level=1)
    doc.add_paragraph(
        "This independent technical audit reviews Team Zetabyte's Capstone project. "
        "The stated goal of the system is to defend healthcare SOC RAG systems from corpus poisoning attacks. "
        "While the system achieves a 0% attack success rate (vouched for) and contains malicious documents, "
        "this is a structural artifact of routing genuine traffic to human review and defaulting to conservative actions, "
        "rather than a result of high-precision automated filtering. The statistical model currently exhibits low predictive power, "
        "and the system is operationally bottlenecked by a 100% false-positive review rate on clean queries in the full system evaluation."
    )
    
    # Architecture
    doc.add_heading('2. Architecture vs Implementation Reality', level=1)
    doc.add_paragraph(
        "The implementation successfully separates the architecture into four levels: Foundation, Observability, Detectors, and Fusion/Response. "
        "However, the theoretical design relies heavily on embedding anomaly detection and NLI cross-encoder entailment, whereas the actual "
        "implementation depends almost entirely on explicit pattern-matching ('injection') and deterministic rules (Tier 1 vs. Tier 3 conflict) "
        "to catch poisoned documents."
    )
    doc.add_paragraph(
        "A key success is 'Escalation Dominance,' which ensures that adding the statistical track can never make the system less safe than "
        "the rules alone. The rule track forces the final disposition to be conservative when models lack confidence or are underpowered."
    )
    
    # Detectors
    doc.add_heading('3. Detector Performance', level=1)
    doc.add_paragraph(
        "The detectors run independently, but their individual efficacy varies significantly from the design claims:"
    )
    ul = doc.add_paragraph(style='List Bullet')
    ul.add_run("Anomaly (k-means):").bold = True
    ul.add_run(" Intentionally the weakest signal. Retained primarily for structural reasons rather than its predictive utility, as it fails to separate subtle semantic attacks.")
    ul = doc.add_paragraph(style='List Bullet')
    ul.add_run("Entailment (NLI cross-encoder):").bold = True
    ul.add_run(" Evaluates whether evidence supports the generated hypothesis. While functional, its performance on this specific corpus is noisy.")
    ul = doc.add_paragraph(style='List Bullet')
    ul.add_run("Injection (Pattern-matching):").bold = True
    ul.add_run(" This is the primary driver of successful detections. However, because it relies on hand-specified patterns created by the team against their own payloads, its generalizability against unseen adversaries is unproven.")
    
    # Safety Guarantee
    doc.add_heading('4. The Safety Guarantee', level=1)
    doc.add_paragraph(
        "The evaluation logs (eval/results/evaluation.json) claim a 0.0% 'vouched for' attack success rate. While mathematically accurate, "
        "the underlying context reveals that this is achieved by declining to accept any responses automatically. "
        "In the full system configuration:"
    )
    ul = doc.add_paragraph(style='List Bullet')
    ul.add_run("Auto-accept rate: 0.0%")
    ul = doc.add_paragraph(style='List Bullet')
    ul.add_run("Human review rate: 60.0%")
    ul = doc.add_paragraph(style='List Bullet')
    ul.add_run("Blocked rate: 40.0%")
    doc.add_paragraph(
        "The statistical fusion model achieves a PR-AUC of 0.270 and ROC-AUC of 0.179. The composite score is restricted to use only "
        "x_conflict, is_tier1, and is_tier3 features because injection and anomaly signals lacked sufficient separation. "
        "Consequently, the system operates safely but creates a substantial queue for human analysts, meaning it is structurally safe but operationally useless in its current tuning."
    )
    
    # Audit Log
    doc.add_heading('5. Audit Log Integrity', level=1)
    doc.add_paragraph(
        "The audit log implementation (logs/audit.py) strictly adheres to the append-only, tamper-evident design. "
        "It successfully implements three layers of enforcement:"
    )
    ul = doc.add_paragraph(style='List Bullet')
    ul.add_run("Schema:").bold = True
    ul.add_run(" analyst_decision is NOT NULL with a CHECK constraint and no DEFAULT value, ensuring no passive data contamination.")
    ul = doc.add_paragraph(style='List Bullet')
    ul.add_run("Separation:").bold = True
    ul.add_run(" Query events and analyst decisions are physically separated into two tables with distinct write paths (AuditLog vs. DecisionWriter).")
    ul = doc.add_paragraph(style='List Bullet')
    ul.add_run("Hash Chaining:").bold = True
    ul.add_run(" Each decision row carries a SHA-256 hash of its contents combined with its predecessor's hash, making the decision history cryptographic evidence rather than merely data.")
    
    # Conclusion
    doc.add_heading('6. Conclusion', level=1)
    doc.add_paragraph(
        "Team Zetabyte has built a robust structural framework for a secure RAG pipeline. Their approach to escalation dominance, "
        "deterministic safety fallbacks, and audit logging is excellent. However, the claims regarding 'AI-driven detection' outpace the "
        "current capabilities of the deployed models. The 0% attack success rate is a product of conservative routing rather than "
        "sophisticated filtering. Future work must focus on improving the baseline separation of the statistical models and reducing "
        "the false-positive rate to make the system operationally viable."
    )

    doc.save('audit_report.docx')
    print("Report generated successfully: audit_report.docx")

if __name__ == '__main__':
    create_report()
