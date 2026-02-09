package com.seheon99.urlsentinel.decision

import com.seheon99.urlsentinel.config.VerdictProperties
import com.seheon99.urlsentinel.rule.RuleResult
import com.seheon99.urlsentinel.rule.Severity
import com.seheon99.urlsentinel.rule.Verdict
import org.springframework.stereotype.Component

/**
 * Default Decision Engine implementation using configurable thresholds.
 *
 * Decision logic:
 * - REJECT if any CRITICAL rule triggers
 * - REJECT if N or more MAJOR rules trigger (configurable threshold)
 * - REJECT if total risk score >= threshold (configurable)
 * - ALLOW otherwise
 */
@Component
class DefaultDecisionEngine(
    private val properties: VerdictProperties,
) : DecisionEngine {

    override fun decide(results: List<RuleResult>): Verdict {
        val triggered = results.filter { it.triggered }

        // Critical rules trigger immediate rejection
        if (triggered.any { it.severity == Severity.CRITICAL }) {
            return Verdict.REJECT
        }

        // Multiple major rules trigger rejection
        val majorCount = triggered.count { it.severity == Severity.MAJOR }
        if (majorCount >= properties.majorCountThreshold) {
            return Verdict.REJECT
        }

        // High total risk score triggers rejection
        val totalScore = triggered.sumOf { it.severity.weight }
        if (totalScore >= properties.riskScoreThreshold) {
            return Verdict.REJECT
        }

        return Verdict.ALLOW
    }
}
