package com.seheon99.urlsentinel.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("urlsentinel.network-features")
data class NetworkFeaturesProperties(
    val enabled: Boolean = true,
    val dns: DnsProperties = DnsProperties(),
    val ssl: SslFeatureProperties = SslFeatureProperties(),
    val http: HttpProperties = HttpProperties(),
    val whois: WhoisProperties = WhoisProperties(),
) {
    data class DnsProperties(
        val enabled: Boolean = true,
        val timeout: Int = 5000,
        val spfEnabled: Boolean = true,
        val mxEnabled: Boolean = true,
        val nsEnabled: Boolean = true,
        val ttlEnabled: Boolean = true,
    )

    data class SslFeatureProperties(
        val enabled: Boolean = true,
    )

    data class HttpProperties(
        val enabled: Boolean = true,
        val connectTimeout: Int = 5000,  // 5 seconds
        val readTimeout: Int = 5000,     // 5 seconds
        val maxRedirects: Int = 10,
    )

    data class WhoisProperties(
        val enabled: Boolean = true,
        val timeout: Int = 10000,
    )
}
