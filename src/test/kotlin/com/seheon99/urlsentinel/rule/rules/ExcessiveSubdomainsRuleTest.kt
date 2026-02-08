package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.config.RuleProperties
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ExcessiveSubdomainsRuleTest {

    private val rule = ExcessiveSubdomainsRule(RuleProperties(maxSubdomains = 3))

    @Test
    fun `normal URL does not trigger`() {
        // www.google.com = 2 dots
        val result = rule.evaluate("https://www.google.com")
        assertFalse(result.triggered)
    }

    @Test
    fun `URL with many subdomains triggers`() {
        // a.b.c.d.evil.com = 5 dots
        val result = rule.evaluate("https://a.b.c.d.evil.com")
        assertTrue(result.triggered)
        assertTrue(result.code == "EXCESSIVE_SUBDOMAINS")
    }

    @Test
    fun `URL at threshold does not trigger`() {
        // www.sub.example.com = 3 dots
        val result = rule.evaluate("https://www.sub.example.com")
        assertFalse(result.triggered)
    }
}
