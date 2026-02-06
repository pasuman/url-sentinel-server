package com.seheon99.urlpolice.rule

import com.seheon99.urlpolice.config.VerdictProperties
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class DefaultVerdictPolicyTest {

    private val policy = DefaultVerdictPolicy(VerdictProperties(majorCountThreshold = 2, riskScoreThreshold = 50))

    @Test
    fun `no triggered rules returns ALLOW`() {
        val results = listOf(
            RuleResult(triggered = false, code = "TEST", severity = Severity.MINOR, message = ""),
        )
        assertEquals(Verdict.ALLOW, policy.decide(results))
    }

    @Test
    fun `single CRITICAL triggers REJECT`() {
        val results = listOf(
            RuleResult(triggered = true, code = "IP_ADDRESS_DOMAIN", severity = Severity.CRITICAL, message = "test"),
        )
        assertEquals(Verdict.REJECT, policy.decide(results))
    }

    @Test
    fun `two MAJOR rules triggers REJECT`() {
        val results = listOf(
            RuleResult(triggered = true, code = "A", severity = Severity.MAJOR, message = "test"),
            RuleResult(triggered = true, code = "B", severity = Severity.MAJOR, message = "test"),
        )
        assertEquals(Verdict.REJECT, policy.decide(results))
    }

    @Test
    fun `single MAJOR does not trigger REJECT`() {
        val results = listOf(
            RuleResult(triggered = true, code = "A", severity = Severity.MAJOR, message = "test"),
        )
        assertEquals(Verdict.ALLOW, policy.decide(results))
    }

    @Test
    fun `risk score at threshold triggers REJECT`() {
        val results = listOf(
            RuleResult(triggered = true, code = "A", severity = Severity.MAJOR, message = "test"),
            RuleResult(triggered = true, code = "B", severity = Severity.MINOR, message = "test"),
            RuleResult(triggered = true, code = "C", severity = Severity.MINOR, message = "test"),
            RuleResult(triggered = true, code = "D", severity = Severity.MINOR, message = "test"),
        )
        // 20 + 10 + 10 + 10 = 50 >= 50
        assertEquals(Verdict.REJECT, policy.decide(results))
    }

    @Test
    fun `only minor rules below threshold returns ALLOW`() {
        val results = listOf(
            RuleResult(triggered = true, code = "A", severity = Severity.MINOR, message = "test"),
            RuleResult(triggered = true, code = "B", severity = Severity.MINOR, message = "test"),
        )
        // 10 + 10 = 20 < 50
        assertEquals(Verdict.ALLOW, policy.decide(results))
    }
}
