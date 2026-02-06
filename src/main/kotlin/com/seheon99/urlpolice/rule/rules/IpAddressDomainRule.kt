package com.seheon99.urlpolice.rule.rules

import com.seheon99.urlpolice.rule.PhishingRule
import com.seheon99.urlpolice.rule.RuleResult
import com.seheon99.urlpolice.rule.Severity
import org.springframework.stereotype.Component
import java.net.URI

@Component
class IpAddressDomainRule : PhishingRule {

    private val ipv4Pattern = Regex("""\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}""")

    override fun evaluate(url: String): RuleResult {
        val host = try {
            URI.create(url).host ?: ""
        } catch (_: Exception) {
            ""
        }

        val triggered = ipv4Pattern.matches(host) || host.startsWith("[")
        return RuleResult(
            triggered = triggered,
            code = "IP_ADDRESS_DOMAIN",
            severity = Severity.CRITICAL,
            message = if (triggered) "URL uses an IP address instead of a domain name" else "",
        )
    }
}
