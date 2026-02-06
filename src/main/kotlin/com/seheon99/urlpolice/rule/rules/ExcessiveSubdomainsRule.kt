package com.seheon99.urlpolice.rule.rules

import com.seheon99.urlpolice.config.RuleProperties
import com.seheon99.urlpolice.rule.PhishingRule
import com.seheon99.urlpolice.rule.RuleResult
import com.seheon99.urlpolice.rule.Severity
import org.springframework.stereotype.Component
import java.net.URI

@Component
class ExcessiveSubdomainsRule(
    private val properties: RuleProperties,
) : PhishingRule {

    override fun evaluate(url: String): RuleResult {
        val host = try {
            URI.create(url).host?.lowercase() ?: ""
        } catch (_: Exception) {
            ""
        }

        val dotCount = host.count { it == '.' }
        val triggered = dotCount > properties.maxSubdomains
        return RuleResult(
            triggered = triggered,
            code = "EXCESSIVE_SUBDOMAINS",
            severity = Severity.MAJOR,
            message = if (triggered) "URL has $dotCount subdomain levels (threshold: ${properties.maxSubdomains})" else "",
        )
    }
}
