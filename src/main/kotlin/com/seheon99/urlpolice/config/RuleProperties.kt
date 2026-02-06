package com.seheon99.urlpolice.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("urlpolice.rules")
data class RuleProperties(
    val maxUrlLength: Int = 200,
    val specialCharThreshold: Int = 8,
    val maxSubdomains: Int = 3,
    val suspiciousKeywords: List<String> = listOf(
        "login", "verify", "secure", "update", "bank", "account",
        "confirm", "suspend", "password", "signin", "credential",
    ),
    val shortenerDomains: List<String> = listOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "rebrand.ly", "bl.ink",
    ),
    val suspiciousTlds: List<String> = listOf(
        "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club",
        "work", "buzz", "cam", "icu",
    ),
    val encodedCharThreshold: Int = 3,
)
