package com.seheon99.urlsentinel.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("urlsentinel.verdict")
data class VerdictProperties(
    val majorCountThreshold: Int = 2,
    val riskScoreThreshold: Int = 50,
)
