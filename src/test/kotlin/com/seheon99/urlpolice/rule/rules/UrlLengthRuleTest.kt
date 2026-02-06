package com.seheon99.urlpolice.rule.rules

import com.seheon99.urlpolice.config.RuleProperties
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UrlLengthRuleTest {

    private val rule = UrlLengthRule(RuleProperties(maxUrlLength = 100))

    @Test
    fun `short URL does not trigger`() {
        val result = rule.evaluate("https://www.google.com")
        assertFalse(result.triggered)
    }

    @Test
    fun `URL exceeding threshold triggers`() {
        val longUrl = "https://www.example.com/" + "a".repeat(200)
        val result = rule.evaluate(longUrl)
        assertTrue(result.triggered)
        assertTrue(result.code == "URL_TOO_LONG")
    }

    @Test
    fun `URL at exact threshold does not trigger`() {
        val url = "a".repeat(100)
        val result = rule.evaluate(url)
        assertFalse(result.triggered)
    }
}
