package com.seheon99.urlpolice.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("urlpolice.verdict")
data class VerdictProperties(
    val majorCountThreshold: Int = 2,
    val riskScoreThreshold: Int = 50,
)
