package com.seheon99.urlsentinel.network

import com.seheon99.urlsentinel.config.NetworkFeaturesProperties
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class NetworkFeaturesServiceTest {

    private val defaultProperties = NetworkFeaturesProperties()

    @Test
    fun `returns empty map when globally disabled`() {
        val properties = NetworkFeaturesProperties(enabled = false)
        val service = NetworkFeaturesService(properties)

        val features = service.collectFeatures("https://example.com")

        assertThat(features).isEmpty()
    }

    @Test
    fun `returns empty map for invalid URLs`() {
        val service = NetworkFeaturesService(defaultProperties)

        val features = service.collectFeatures("not-a-url")

        assertThat(features).isEmpty()
    }

    @Test
    fun `SSL feature is 0 for HTTP URLs`() {
        val service = NetworkFeaturesService(defaultProperties)

        val features = service.collectFeatures("http://example.com")

        assertThat(features["tls_ssl_certificate"]).isEqualTo(0.0)
    }

    @Test
    fun `DNS features disabled when configuration is false`() {
        val properties = NetworkFeaturesProperties(
            dns = NetworkFeaturesProperties.DnsProperties(enabled = false)
        )
        val service = NetworkFeaturesService(properties)

        val features = service.collectFeatures("http://example.com")

        assertThat(features).doesNotContainKey("time_response")
        assertThat(features).doesNotContainKey("qty_ip_resolved")
    }

    @Test
    fun `SSL features disabled when configuration is false`() {
        val properties = NetworkFeaturesProperties(
            ssl = NetworkFeaturesProperties.SslFeatureProperties(enabled = false)
        )
        val service = NetworkFeaturesService(properties)

        val features = service.collectFeatures("https://example.com")

        assertThat(features).doesNotContainKey("tls_ssl_certificate")
    }

    @Test
    fun `HTTP features disabled when configuration is false`() {
        val properties = NetworkFeaturesProperties(
            http = NetworkFeaturesProperties.HttpProperties(enabled = false)
        )
        val service = NetworkFeaturesService(properties)

        val features = service.collectFeatures("http://example.com")

        assertThat(features).doesNotContainKey("qty_redirects")
    }

    // Integration tests - disabled by default (require network access)
    // Uncomment to test against real endpoints

    // @Test
    // fun `collects DNS features for real domain`() {
    //     val service = NetworkFeaturesService(defaultProperties)
    //
    //     val features = service.collectFeatures("https://www.google.com")
    //
    //     assertThat(features["time_response"]).isGreaterThan(0.0)
    //     assertThat(features["qty_ip_resolved"]).isGreaterThan(0.0)
    // }

    // @Test
    // fun `SSL feature is 1 when certificate is valid`() {
    //     val service = NetworkFeaturesService(defaultProperties)
    //
    //     val features = service.collectFeatures("https://www.google.com")
    //
    //     assertThat(features["tls_ssl_certificate"]).isEqualTo(1.0)
    // }
}
