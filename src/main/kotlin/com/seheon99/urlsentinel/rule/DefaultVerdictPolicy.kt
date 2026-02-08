package com.seheon99.urlsentinel.rule

import com.seheon99.urlsentinel.config.VerdictProperties
import org.springframework.stereotype.Component

@Component
class DefaultVerdictPolicy(
    private val properties: VerdictProperties,
) : VerdictPolicy {

    override fun decide(results: List<RuleResult>): Verdict {
        val triggered = results.filter { it.triggered }

        if (triggered.any { it.severity == Severity.CRITICAL }) {
            return Verdict.REJECT
        }

        val majorCount = triggered.count { it.severity == Severity.MAJOR }
        if (majorCount >= properties.majorCountThreshold) {
            return Verdict.REJECT
        }

        val totalScore = triggered.sumOf { it.severity.weight }
        if (totalScore >= properties.riskScoreThreshold) {
            return Verdict.REJECT
        }

        return Verdict.ALLOW
    }
}
