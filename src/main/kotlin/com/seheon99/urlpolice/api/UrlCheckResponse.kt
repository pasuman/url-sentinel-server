package com.seheon99.urlpolice.api

import com.seheon99.urlpolice.rule.Verdict

data class UrlCheckResponse(
    val verdict: Verdict,
    val reasons: List<ReasonDetail>,
    val riskScore: Int,
)

data class ReasonDetail(
    val code: String,
    val severity: String,
    val message: String,
)
