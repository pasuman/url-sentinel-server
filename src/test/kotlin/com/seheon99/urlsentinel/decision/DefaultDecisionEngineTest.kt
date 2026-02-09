package com.seheon99.urlsentinel.decision

import com.seheon99.urlsentinel.config.VerdictProperties
import com.seheon99.urlsentinel.rule.RuleResult
import com.seheon99.urlsentinel.rule.Severity
import com.seheon99.urlsentinel.rule.Verdict
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class DefaultDecisionEngineTest {

    private val properties = VerdictProperties(
        majorCountThreshold = 2,
        riskScoreThreshold = 50,
    )
    private val engine = DefaultDecisionEngine(properties)

    @Test
    fun `returns ALLOW when no rules triggered`() {
        val results = listOf(
            RuleResult(triggered = false, code = "RULE_1", severity = Severity.MINOR, message = ""),
        )

        assertEquals(Verdict.ALLOW, engine.decide(results))
    }

    @Test
    fun `returns REJECT when CRITICAL rule triggers`() {
        val results = listOf(
            RuleResult(triggered = true, code = "CRITICAL_RULE", severity = Severity.CRITICAL, message = "Critical"),
        )

        assertEquals(Verdict.REJECT, engine.decide(results))
    }

    @Test
    fun `returns REJECT when major count threshold exceeded`() {
        val results = listOf(
            RuleResult(triggered = true, code = "MAJOR_1", severity = Severity.MAJOR, message = "Major 1"),
            RuleResult(triggered = true, code = "MAJOR_2", severity = Severity.MAJOR, message = "Major 2"),
        )

        assertEquals(Verdict.REJECT, engine.decide(results))
    }

    @Test
    fun `returns REJECT when risk score threshold exceeded`() {
        val results = listOf(
            RuleResult(triggered = true, code = "MAJOR_1", severity = Severity.MAJOR, message = "Major"),  // 20
            RuleResult(triggered = true, code = "MINOR_1", severity = Severity.MINOR, message = "Minor 1"),  // 10
            RuleResult(triggered = true, code = "MINOR_2", severity = Severity.MINOR, message = "Minor 2"),  // 10
            RuleResult(triggered = true, code = "MINOR_3", severity = Severity.MINOR, message = "Minor 3"),  // 10
        )
        // Total: 50, meets threshold

        assertEquals(Verdict.REJECT, engine.decide(results))
    }

    @Test
    fun `returns ALLOW when thresholds not met`() {
        val results = listOf(
            RuleResult(triggered = true, code = "MAJOR_1", severity = Severity.MAJOR, message = "Major"),  // 20
            RuleResult(triggered = true, code = "MINOR_1", severity = Severity.MINOR, message = "Minor"),  // 10
        )
        // Total: 30, below threshold; only 1 major

        assertEquals(Verdict.ALLOW, engine.decide(results))
    }
}
