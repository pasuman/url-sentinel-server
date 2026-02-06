package com.seheon99.urlpolice.rule

import com.seheon99.urlpolice.config.VerdictProperties
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RuleEngineTest {

    @Test
    fun `engine aggregates results from all rules`() {
        val rule1 = PhishingRule { RuleResult(triggered = true, code = "RULE_1", severity = Severity.MAJOR, message = "hit") }
        val rule2 = PhishingRule { RuleResult(triggered = false, code = "RULE_2", severity = Severity.MINOR, message = "") }
        val rule3 = PhishingRule { RuleResult(triggered = true, code = "RULE_3", severity = Severity.MINOR, message = "hit") }

        val engine = RuleEngine(
            rules = listOf(rule1, rule2, rule3),
            verdictPolicy = DefaultVerdictPolicy(VerdictProperties()),
        )

        val response = engine.evaluate("https://test.com")
        assertEquals(2, response.reasons.size)
        assertEquals(30, response.riskScore) // 20 + 10
        assertTrue(response.reasons.any { it.code == "RULE_1" })
        assertTrue(response.reasons.any { it.code == "RULE_3" })
    }

    @Test
    fun `engine caps risk score at 100`() {
        val rules = (1..5).map { i ->
            PhishingRule { RuleResult(triggered = true, code = "RULE_$i", severity = Severity.CRITICAL, message = "hit") }
        }

        val engine = RuleEngine(
            rules = rules,
            verdictPolicy = DefaultVerdictPolicy(VerdictProperties()),
        )

        val response = engine.evaluate("https://test.com")
        assertEquals(100, response.riskScore) // 5 * 40 = 200, capped at 100
        assertEquals(Verdict.REJECT, response.verdict)
    }

    @Test
    fun `safe URL returns ALLOW with no reasons`() {
        val rule = PhishingRule { RuleResult(triggered = false, code = "SAFE", severity = Severity.MINOR, message = "") }

        val engine = RuleEngine(
            rules = listOf(rule),
            verdictPolicy = DefaultVerdictPolicy(VerdictProperties()),
        )

        val response = engine.evaluate("https://www.google.com")
        assertEquals(Verdict.ALLOW, response.verdict)
        assertTrue(response.reasons.isEmpty())
        assertEquals(0, response.riskScore)
    }
}
