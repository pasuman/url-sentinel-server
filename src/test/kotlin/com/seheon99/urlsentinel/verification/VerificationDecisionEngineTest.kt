package com.seheon99.urlsentinel.verification

import com.seheon99.urlsentinel.config.VerificationProperties
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class VerificationDecisionEngineTest {

    private val properties = VerificationProperties(
        legitimateThreshold = 70,
        suspiciousThreshold = 20
    )
    private val engine = VerificationDecisionEngine(properties)

    @Test
    fun `returns LIKELY_LEGITIMATE when score is 70 or above`() {
        val results = listOf(
            CheckResult("TEST1", true, 50, "Test"),
            CheckResult("TEST2", true, 30, "Test")
        )

        val verdict = engine.decide(results)

        assertEquals(VerificationVerdict.LIKELY_LEGITIMATE, verdict)
    }

    @Test
    fun `returns LIKELY_LEGITIMATE for score exactly 70`() {
        val results = listOf(
            CheckResult("TEST1", true, 70, "Test")
        )

        val verdict = engine.decide(results)

        assertEquals(VerificationVerdict.LIKELY_LEGITIMATE, verdict)
    }

    @Test
    fun `returns SUSPICIOUS when score is between 20 and 69`() {
        val results = listOf(
            CheckResult("TEST1", true, 30, "Test"),
            CheckResult("TEST2", false, -10, "Test")
        )

        val verdict = engine.decide(results)

        assertEquals(VerificationVerdict.SUSPICIOUS, verdict)
    }

    @Test
    fun `returns SUSPICIOUS for score exactly 20`() {
        val results = listOf(
            CheckResult("TEST1", true, 20, "Test")
        )

        val verdict = engine.decide(results)

        assertEquals(VerificationVerdict.SUSPICIOUS, verdict)
    }

    @Test
    fun `returns LIKELY_INTERCEPTION when score is below 20`() {
        val results = listOf(
            CheckResult("TEST1", false, -40, "Test"),
            CheckResult("TEST2", false, -30, "Test")
        )

        val verdict = engine.decide(results)

        assertEquals(VerificationVerdict.LIKELY_INTERCEPTION, verdict)
    }

    @Test
    fun `returns LIKELY_INTERCEPTION for score 0`() {
        val results = listOf(
            CheckResult("TEST1", false, 0, "Test")
        )

        val verdict = engine.decide(results)

        assertEquals(VerificationVerdict.LIKELY_INTERCEPTION, verdict)
    }

    @Test
    fun `handles mixed positive and negative scores`() {
        val results = listOf(
            CheckResult("PASS1", true, 50, "Test"),
            CheckResult("FAIL1", false, -40, "Test"),
            CheckResult("PASS2", true, 20, "Test"),
            CheckResult("FAIL2", false, -10, "Test")
        )
        // Total: 50 - 40 + 20 - 10 = 20

        val verdict = engine.decide(results)

        assertEquals(VerificationVerdict.SUSPICIOUS, verdict)
    }
}
