package com.seheon99.urlsentinel.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("urlsentinel.ssl")
data class SslProperties(
    val connectTimeout: Int = 10000,  // 10 seconds
    val readTimeout: Int = 10000,     // 10 seconds
)
