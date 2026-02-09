package com.seheon99.urlsentinel.decision

import com.seheon99.urlsentinel.rule.RuleResult
import com.seheon99.urlsentinel.rule.Verdict

/**
 * Decision Engine: Aggregates rule results into a final verdict (ALLOW/REJECT).
 *
 * This component applies policy logic to determine whether a URL should be
 * allowed or rejected based on the triggered rules and their severities.
 */
fun interface DecisionEngine {
    fun decide(results: List<RuleResult>): Verdict
}
