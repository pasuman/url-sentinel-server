package com.seheon99.urlsentinel.rule

import com.seheon99.urlsentinel.api.ReasonDetail
import com.seheon99.urlsentinel.api.UrlCheckResponse
import org.springframework.stereotype.Service

@Service
class RuleEngine(
    private val rules: List<PhishingRule>,
    private val verdictPolicy: VerdictPolicy,
) {

    fun evaluate(url: String): UrlCheckResponse {
        val results = rules.map { it.evaluate(url) }
        val triggered = results.filter { it.triggered }
        val verdict = verdictPolicy.decide(results)
        val riskScore = triggered.sumOf { it.severity.weight }.coerceAtMost(100)

        return UrlCheckResponse(
            verdict = verdict,
            reasons = triggered.map { ReasonDetail(it.code, it.severity.name, it.message) },
            riskScore = riskScore,
        )
    }
}
