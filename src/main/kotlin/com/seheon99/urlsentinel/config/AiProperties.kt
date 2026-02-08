package com.seheon99.urlsentinel.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("urlsentinel.ai")
data class AiProperties(
    val baseUrl: String = "http://localhost:8000",
)
