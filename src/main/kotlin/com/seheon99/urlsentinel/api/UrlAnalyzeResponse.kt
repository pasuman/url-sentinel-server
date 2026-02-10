package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.rule.Verdict

/**
 * Response from /analyze endpoint.
 * Simplified to focus on URL phishing detection only.
 */
data class UrlAnalyzeResponse(
    val verdict: Verdict,
    val reasons: List<ReasonDetail>,
    val riskScore: Int
)

data class ReasonDetail(
    val code: String,
    val severity: String,
    val message: String,
)
