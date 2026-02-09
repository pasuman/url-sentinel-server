package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.verification.ClientObservation

data class UrlAnalyzeRequest(
    val url: String,
    val clientObservation: ClientObservation  // MANDATORY - SSL verification always performed first
)
