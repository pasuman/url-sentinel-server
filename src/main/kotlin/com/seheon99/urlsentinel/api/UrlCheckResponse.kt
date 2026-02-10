package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.rule.Verdict

data class UrlCheckResponse(
    val verdict: Verdict,
    val reasons: List<ReasonDetail>,
    val riskScore: Int,
)
