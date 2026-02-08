package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.config.RuleProperties
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EncodedCharactersRuleTest {

    private val rule = EncodedCharactersRule(RuleProperties(encodedCharThreshold = 3))

    @Test
    fun `normal URL does not trigger`() {
        val result = rule.evaluate("https://www.google.com/search?q=hello")
        assertFalse(result.triggered)
    }

    @Test
    fun `URL with many encoded chars triggers`() {
        val result = rule.evaluate("https://evil.com/%2F%2E%2E%2F%2E%2E")
        assertTrue(result.triggered)
        assertTrue(result.code == "ENCODED_CHARACTERS")
    }

    @Test
    fun `URL with few encoded chars does not trigger`() {
        val result = rule.evaluate("https://example.com/path%20name")
        assertFalse(result.triggered)
    }
}
