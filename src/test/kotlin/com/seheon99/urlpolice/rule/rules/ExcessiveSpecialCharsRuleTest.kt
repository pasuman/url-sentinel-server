package com.seheon99.urlpolice.rule.rules

import com.seheon99.urlpolice.config.RuleProperties
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ExcessiveSpecialCharsRuleTest {

    private val rule = ExcessiveSpecialCharsRule(RuleProperties(specialCharThreshold = 5))

    @Test
    fun `normal URL does not trigger`() {
        val result = rule.evaluate("https://www.google.com")
        assertFalse(result.triggered)
    }

    @Test
    fun `URL with many special chars triggers`() {
        val result = rule.evaluate("https://evil.site.com/a?b=c&d=e&f=g&h=i%20%30%40")
        assertTrue(result.triggered)
        assertTrue(result.code == "EXCESSIVE_SPECIAL_CHARS")
    }

    @Test
    fun `URL at threshold does not trigger`() {
        // Exactly 5 special chars: 3 dots + 1 question + 1 equals
        val result = rule.evaluate("https://www.example.com/path?key=value")
        assertFalse(result.triggered)
    }
}
