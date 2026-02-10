package com.seheon99.urlsentinel.rule

import com.seheon99.urlsentinel.api.ReasonDetail
import com.seheon99.urlsentinel.api.UrlCheckResponse
import com.seheon99.urlsentinel.decision.DecisionEngine
import org.springframework.stereotype.Service

/**
 * Rule Engine: Executes all phishing detection rules and collects results.
 *
 * This component coordinates the execution of individual rules and delegates
 * the final verdict decision to the Decision Engine.
 */
@Service
class RuleEngine(
    private val rules: List<PhishingRule>,
    private val decisionEngine: DecisionEngine,
) {

    fun evaluate(url: String): UrlCheckResponse {
        val results = rules.map { it.evaluate(url) }
        val triggered = results.filter { it.triggered }
        val verdict = decisionEngine.decide(results)
        val riskScore = triggered.sumOf { it.score.toInt() }.coerceAtMost(100)

        return UrlCheckResponse(
            verdict = verdict,
            reasons = triggered.map { ReasonDetail(it.code, it.severity.name, it.message) },
            riskScore = riskScore,
        )
    }
}
