package com.seheon99.urlsentinel.rule

data class RuleResult(
    val triggered: Boolean,
    val code: String,
    val severity: Severity,
    val message: String,
)
