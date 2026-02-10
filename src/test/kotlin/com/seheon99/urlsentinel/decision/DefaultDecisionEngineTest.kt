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
            RuleResult(triggered = false, code = "RULE_1", severity = Severity.MINOR, message = "", score = 10.0),
        )

        assertEquals(Verdict.ALLOW, engine.decide(results))
    }

    @Test
    fun `returns REJECT when CRITICAL rule triggers`() {
        val results = listOf(
            RuleResult(triggered = true, code = "CRITICAL_RULE", severity = Severity.CRITICAL, message = "Critical", score = 40.0),
        )

        assertEquals(Verdict.REJECT, engine.decide(results))
    }

    @Test
    fun `returns REJECT when major count threshold exceeded`() {
        val results = listOf(
            RuleResult(triggered = true, code = "MAJOR_1", severity = Severity.MAJOR, message = "Major 1", score = 20.0),
            RuleResult(triggered = true, code = "MAJOR_2", severity = Severity.MAJOR, message = "Major 2", score = 20.0),
        )

        assertEquals(Verdict.REJECT, engine.decide(results))
    }

    @Test
    fun `returns REJECT when risk score threshold exceeded`() {
        val results = listOf(
            RuleResult(triggered = true, code = "MAJOR_1", severity = Severity.MAJOR, message = "Major", score = 20.0),
            RuleResult(triggered = true, code = "MINOR_1", severity = Severity.MINOR, message = "Minor 1", score = 10.0),
            RuleResult(triggered = true, code = "MINOR_2", severity = Severity.MINOR, message = "Minor 2", score = 10.0),
            RuleResult(triggered = true, code = "MINOR_3", severity = Severity.MINOR, message = "Minor 3", score = 10.0),
        )
        // Total: 50, meets threshold

        assertEquals(Verdict.REJECT, engine.decide(results))
    }

    @Test
    fun `returns ALLOW when thresholds not met`() {
        val results = listOf(
            RuleResult(triggered = true, code = "MAJOR_1", severity = Severity.MAJOR, message = "Major", score = 20.0),
            RuleResult(triggered = true, code = "MINOR_1", severity = Severity.MINOR, message = "Minor", score = 10.0),
        )
        // Total: 30, below threshold; only 1 major

        assertEquals(Verdict.ALLOW, engine.decide(results))
    }

    @Test
    fun `uses custom score when provided`() {
        val results = listOf(
            RuleResult(triggered = true, code = "AI_MODEL", severity = Severity.MAJOR, message = "AI", score = 38.0),
            RuleResult(triggered = true, code = "MINOR_1", severity = Severity.MINOR, message = "Minor", score = 10.0),
        )
        // Total: 38 + 10 = 48, below threshold (50)

        assertEquals(Verdict.ALLOW, engine.decide(results))
    }

    @Test
    fun `all rules contribute scores correctly`() {
        val results = listOf(
            RuleResult(triggered = true, code = "AI_MODEL", severity = Severity.MAJOR, message = "AI", score = 20.0),  // Custom: 20
            RuleResult(triggered = true, code = "MAJOR_1", severity = Severity.MAJOR, message = "Major", score = 20.0),  // 20
            RuleResult(triggered = true, code = "MINOR_1", severity = Severity.MINOR, message = "Minor", score = 10.0),  // 10
        )
        // Total: 20 + 20 + 10 = 50, meets threshold

        assertEquals(Verdict.REJECT, engine.decide(results))
    }

    @Test
    fun `low probability AI score allows URL despite other rules`() {
        val results = listOf(
            RuleResult(triggered = true, code = "AI_MODEL", severity = Severity.MAJOR, message = "AI", score = 5.0),  // Low probability
            RuleResult(triggered = true, code = "MINOR_1", severity = Severity.MINOR, message = "Minor 1", score = 10.0),
            RuleResult(triggered = true, code = "MINOR_2", severity = Severity.MINOR, message = "Minor 2", score = 10.0),
        )
        // Total: 5 + 10 + 10 = 25, below threshold (50)

        assertEquals(Verdict.ALLOW, engine.decide(results))
    }

    @Test
    fun `high probability AI score contributes to rejection`() {
        val results = listOf(
            RuleResult(triggered = true, code = "AI_MODEL", severity = Severity.MAJOR, message = "AI", score = 35.0),  // High probability
            RuleResult(triggered = true, code = "MINOR_1", severity = Severity.MINOR, message = "Minor 1", score = 10.0),
            RuleResult(triggered = true, code = "MINOR_2", severity = Severity.MINOR, message = "Minor 2", score = 10.0),
        )
        // Total: 35 + 10 + 10 = 55, exceeds threshold (50)

        assertEquals(Verdict.REJECT, engine.decide(results))
    }
}
