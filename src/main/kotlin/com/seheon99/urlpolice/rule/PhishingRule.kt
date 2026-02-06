package com.seheon99.urlpolice.rule

fun interface PhishingRule {
    fun evaluate(url: String): RuleResult
}
