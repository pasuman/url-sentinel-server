package com.seheon99.urlpolice.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("urlpolice.ai")
data class AiProperties(
    val baseUrl: String = "http://localhost:8000",
)
