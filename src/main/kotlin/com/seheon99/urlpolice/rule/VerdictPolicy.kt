package com.seheon99.urlpolice.rule

fun interface VerdictPolicy {
    fun decide(results: List<RuleResult>): Verdict
}
