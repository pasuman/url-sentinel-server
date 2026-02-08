package com.seheon99.urlsentinel.rule

fun interface PhishingRule {
    fun evaluate(url: String): RuleResult
}
