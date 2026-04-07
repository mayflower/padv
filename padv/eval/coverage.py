from __future__ import annotations

from padv.models import EvidenceBundle

def evaluate_run_coverage(bundles: list[EvidenceBundle]) -> dict[str, str]:
    coverage: dict[str, str] = {}
    
    by_class: dict[str, list[EvidenceBundle]] = {}
    for b in bundles:
        vc = str(b.candidate.vuln_class).strip()
        if not vc:
            continue
        if vc not in by_class:
            by_class[vc] = []
        by_class[vc].append(b)
        
    for vc, class_bundles in by_class.items():
        status = "NONE"
        
        for b in class_bundles:
            outcome = b.candidate_outcome
            
            if outcome == "VALIDATED":
                status = "FULL"
                break
                
            if outcome == "REFUTED":
                strong_witness = False
                for pr in b.positive_runtime:
                    if pr.witness_evidence and pr.witness_evidence.witness_flags:
                        strong_witness = True
                        break
                
                if strong_witness and status != "FULL":
                    status = "PARTIAL"
        
        coverage[vc] = status
        
    return coverage