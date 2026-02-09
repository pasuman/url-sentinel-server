package com.seheon99.urlsentinel.api

data class SslVerifyRequest(
    val url: String,
    val clientFingerprint: String,
)
