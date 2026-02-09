package com.seheon99.urlsentinel.api

data class UrlAnalyzeRequest(
    val url: String,
    val clientFingerprint: String? = null,  // Optional - if provided, also perform SSL verification
)
