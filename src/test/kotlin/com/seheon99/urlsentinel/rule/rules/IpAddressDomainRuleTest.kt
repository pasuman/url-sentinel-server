package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.rule.Severity
import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class IpAddressDomainRuleTest {

    private val rule = IpAddressDomainRule()

    @Test
    fun `normal domain does not trigger`() {
        val result = rule.evaluate("https://www.google.com")
        assertFalse(result.triggered)
    }

    @Test
    fun `IPv4 address triggers`() {
        val result = rule.evaluate("http://192.168.1.1/login")
        assertTrue(result.triggered)
        assertTrue(result.severity == Severity.CRITICAL)
        assertTrue(result.code == "IP_ADDRESS_DOMAIN")
    }

    @Test
    fun `IPv6 address triggers`() {
        val result = rule.evaluate("http://[::1]/path")
        assertTrue(result.triggered)
    }

    @Test
    fun `malformed URL does not crash`() {
        val result = rule.evaluate("not a url at all")
        assertFalse(result.triggered)
    }
}
