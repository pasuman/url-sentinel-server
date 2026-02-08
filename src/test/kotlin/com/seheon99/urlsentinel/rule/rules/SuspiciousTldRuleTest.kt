package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.config.RuleProperties
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SuspiciousTldRuleTest {

    private val rule = SuspiciousTldRule(RuleProperties())

    @Test
    fun `com TLD does not trigger`() {
        val result = rule.evaluate("https://www.google.com")
        assertFalse(result.triggered)
    }

    @Test
    fun `xyz TLD triggers`() {
        val result = rule.evaluate("https://evil-site.xyz")
        assertTrue(result.triggered)
        assertTrue(result.code == "SUSPICIOUS_TLD")
    }

    @Test
    fun `tk TLD triggers`() {
        val result = rule.evaluate("https://free-stuff.tk")
        assertTrue(result.triggered)
    }

    @Test
    fun `org TLD does not trigger`() {
        val result = rule.evaluate("https://wikipedia.org")
        assertFalse(result.triggered)
    }
}
