package com.seheon99.urlsentinel.network

import com.seheon99.urlsentinel.config.NetworkFeaturesProperties
import com.seheon99.urlsentinel.ssl.SslCertificateService
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock

class NetworkFeaturesServiceTest {

    private val sslCertificateService = mock(SslCertificateService::class.java)
    private val defaultProperties = NetworkFeaturesProperties()

    @Test
    fun `returns empty map when globally disabled`() {
        val properties = NetworkFeaturesProperties(enabled = false)
        val service = NetworkFeaturesService(properties, sslCertificateService)

        val features = service.collectFeatures("https://example.com")

        assertThat(features).isEmpty()
    }

    @Test
    fun `returns empty map for invalid URLs`() {
        val service = NetworkFeaturesService(defaultProperties, sslCertificateService)

        val features = service.collectFeatures("not-a-url")

        assertThat(features).isEmpty()
    }

    @Test
    fun `SSL feature is 0 for HTTP URLs`() {
        val service = NetworkFeaturesService(defaultProperties, sslCertificateService)

        val features = service.collectFeatures("http://example.com")

        assertThat(features["tls_ssl_certificate"]).isEqualTo(0.0)
    }

    @Test
    fun `SSL feature is 1 when certificate is valid`() {
        // Mock successful certificate fetch
        `when`(sslCertificateService.fetchCertificate("https://example.com"))
            .thenReturn(org.mockito.Mockito.mock(java.security.cert.X509Certificate::class.java))

        val service = NetworkFeaturesService(defaultProperties, sslCertificateService)

        val features = service.collectFeatures("https://example.com")

        assertThat(features["tls_ssl_certificate"]).isEqualTo(1.0)
    }

    @Test
    fun `SSL feature is -1 when certificate fetch fails`() {
        // Mock certificate fetch failure with RuntimeException (unchecked)
        `when`(sslCertificateService.fetchCertificate("https://example.com"))
            .thenThrow(RuntimeException("SSL handshake failed"))

        val service = NetworkFeaturesService(defaultProperties, sslCertificateService)

        val features = service.collectFeatures("https://example.com")

        assertThat(features["tls_ssl_certificate"]).isEqualTo(-1.0)
    }

    @Test
    fun `DNS features disabled when configuration is false`() {
        val properties = NetworkFeaturesProperties(
            dns = NetworkFeaturesProperties.DnsProperties(enabled = false)
        )
        val service = NetworkFeaturesService(properties, sslCertificateService)

        val features = service.collectFeatures("http://example.com")

        assertThat(features).doesNotContainKey("time_response")
        assertThat(features).doesNotContainKey("qty_ip_resolved")
    }

    @Test
    fun `SSL features disabled when configuration is false`() {
        val properties = NetworkFeaturesProperties(
            ssl = NetworkFeaturesProperties.SslFeatureProperties(enabled = false)
        )
        val service = NetworkFeaturesService(properties, sslCertificateService)

        val features = service.collectFeatures("https://example.com")

        assertThat(features).doesNotContainKey("tls_ssl_certificate")
    }

    @Test
    fun `HTTP features disabled when configuration is false`() {
        val properties = NetworkFeaturesProperties(
            http = NetworkFeaturesProperties.HttpProperties(enabled = false)
        )
        val service = NetworkFeaturesService(properties, sslCertificateService)

        val features = service.collectFeatures("http://example.com")

        assertThat(features).doesNotContainKey("qty_redirects")
    }

    // Integration test - disabled by default (requires network access)
    // @Test
    // fun `collects DNS features for real domain`() {
    //     val service = NetworkFeaturesService(defaultProperties, sslCertificateService)
    //
    //     val features = service.collectFeatures("https://www.google.com")
    //
    //     assertThat(features["time_response"]).isGreaterThan(0.0)
    //     assertThat(features["qty_ip_resolved"]).isGreaterThan(0.0)
    // }
}
