use crate::carve::CarvedFile;

#[derive(Debug, Clone)]
pub struct ScoreBreakdown {
    pub signature_match: f32,
    pub metadata_intact: f32,
    pub fragment_coverage: f32,
    pub overwrite_risk: f32,
    pub type_resilience: f32,
    pub score: u8,
}

/// Implements the exact formula from the project plan (§6.4):
/// score = (sig*0.30 + meta*0.25 + frag*0.25 + (1-overwrite)*0.10 + resilience*0.10) * 100
pub fn score(file: &CarvedFile) -> ScoreBreakdown {
    let signature_match = file.signature_match;
    // A complete file (footer found) implies intact structural metadata;
    // a truncated carve implies partial/no trailing metadata.
    let metadata_intact = if file.complete { 0.9 } else { 0.35 };
    let fragment_coverage = file.fragment_coverage;
    // Entropy is NOT treated as proof of overwrite. Compressed/encrypted
    // files are naturally high-entropy. Until allocation/deallocation evidence
    // is available, overwrite risk is conservative and driven only by
    // structural completeness/coverage.
    let overwrite_risk = if file.complete {
        0.05
    } else {
        (1.0 - file.fragment_coverage).clamp(0.15, 0.75)
    };
    let type_resilience: f32 = match file.file_type.as_str() {
        "image" | "document" => 0.95,
        "archive" => 0.85,
        "audio" | "video" => 0.75,
        _ => 0.7,
    };

    let raw = signature_match * 0.30
        + metadata_intact * 0.25
        + fragment_coverage * 0.25
        + (1.0 - overwrite_risk) * 0.10
        + type_resilience * 0.10;

    let score = (raw * 100.0).round().clamp(4.0, 99.0) as u8;

    ScoreBreakdown {
        signature_match,
        metadata_intact,
        fragment_coverage,
        overwrite_risk,
        type_resilience,
        score,
    }
}

pub fn label(score: u8) -> &'static str {
    match score {
        95..=100 => "Perfect Recovery",
        75..=94 => "Likely Recoverable",
        50..=74 => "Partial Recovery",
        _ => "Try Advanced Mode",
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryConfidence {
    pub signature_confidence: f32,
    pub metadata_confidence: f32,
    pub structural_confidence: f32,
    pub fragment_coverage: f32,
    pub read_success: f32,
    pub overwrite_evidence: f32,
    pub format_resilience: f32,
    pub final_score: u8,
    pub confidence_level: String,
    pub explanation: String,
}

pub fn unified_confidence(
    signature: f32,
    metadata: f32,
    structural: f32,
    fragment: f32,
    read_success: f32,
    overwrite_evidence: f32,
    resilience: f32,
) -> RecoveryConfidence {
    let raw = signature * 0.20
        + metadata * 0.20
        + structural * 0.20
        + fragment * 0.15
        + read_success * 0.15
        + (1.0 - overwrite_evidence.clamp(0.0, 1.0)) * 0.05
        + resilience * 0.05;
    let final_score = (raw * 100.0).round().clamp(0.0, 100.0) as u8;
    let confidence_level = match final_score {
        95..=100 => "PERFECT",
        80..=94 => "HIGH",
        60..=79 => "MEDIUM",
        1..=59 => "LOW",
        0 => "UNRECOVERABLE",
        _ => "UNKNOWN",
    }
    .to_string();
    let explanation=format!("signature={:.2}, metadata={:.2}, structure={:.2}, coverage={:.2}, read={:.2}, overwrite={:.2}",signature,metadata,structural,fragment,read_success,overwrite_evidence);
    RecoveryConfidence {
        signature_confidence: signature,
        metadata_confidence: metadata,
        structural_confidence: structural,
        fragment_coverage: fragment,
        read_success,
        overwrite_evidence,
        format_resilience: resilience,
        final_score,
        confidence_level,
        explanation,
    }
}
