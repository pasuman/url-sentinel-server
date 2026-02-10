package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.config.RuleProperties
import com.seheon99.urlsentinel.rule.PhishingRule
import com.seheon99.urlsentinel.rule.RuleResult
import com.seheon99.urlsentinel.rule.Severity
import org.springframework.stereotype.Component
import java.net.URI

@Component
class UrlShortenerRule(
    private val properties: RuleProperties,
) : PhishingRule {

    override fun evaluate(url: String): RuleResult {
        val host = try {
            URI.create(url).host?.lowercase() ?: ""
        } catch (_: Exception) {
            ""
        }

        val triggered = properties.shortenerDomains.any { host == it || host.endsWith(".$it") }
        return RuleResult(
            triggered = triggered,
            code = "URL_SHORTENER",
            severity = Severity.MAJOR,
            message = if (triggered) "URL uses a known URL shortener service" else "",
            score = 20.0,
        )
    }
}
