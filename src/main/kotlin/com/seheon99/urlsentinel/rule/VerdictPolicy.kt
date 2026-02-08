package com.seheon99.urlsentinel.rule

fun interface VerdictPolicy {
    fun decide(results: List<RuleResult>): Verdict
}
