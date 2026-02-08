package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.config.RuleProperties
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UrlShortenerRuleTest {

    private val rule = UrlShortenerRule(RuleProperties())

    @Test
    fun `normal URL does not trigger`() {
        val result = rule.evaluate("https://www.google.com")
        assertFalse(result.triggered)
    }

    @Test
    fun `bit ly triggers`() {
        val result = rule.evaluate("https://bit.ly/abc123")
        assertTrue(result.triggered)
        assertTrue(result.code == "URL_SHORTENER")
    }

    @Test
    fun `tinyurl triggers`() {
        val result = rule.evaluate("https://tinyurl.com/xyz")
        assertTrue(result.triggered)
    }

    @Test
    fun `domain containing shortener name but not matching does not trigger`() {
        val result = rule.evaluate("https://notbit.ly.example.com/path")
        assertFalse(result.triggered)
    }
}
