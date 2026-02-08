package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.config.RuleProperties
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SuspiciousKeywordRuleTest {

    private val rule = SuspiciousKeywordRule(RuleProperties())

    @Test
    fun `safe URL does not trigger`() {
        val result = rule.evaluate("https://www.google.com/search?q=weather")
        assertFalse(result.triggered)
    }

    @Test
    fun `URL with login keyword triggers`() {
        val result = rule.evaluate("https://evil.com/login")
        assertTrue(result.triggered)
        assertTrue(result.message.contains("login"))
    }

    @Test
    fun `URL with multiple keywords triggers and reports all`() {
        val result = rule.evaluate("https://evil.com/login/verify/password")
        assertTrue(result.triggered)
        assertTrue(result.message.contains("login"))
        assertTrue(result.message.contains("verify"))
        assertTrue(result.message.contains("password"))
    }

    @Test
    fun `case insensitive matching`() {
        val result = rule.evaluate("https://evil.com/LOGIN/VERIFY")
        assertTrue(result.triggered)
    }
}
