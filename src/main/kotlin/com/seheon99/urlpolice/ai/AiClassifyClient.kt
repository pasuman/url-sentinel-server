package com.seheon99.urlpolice.ai

import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient

data class AiClassifyRequest(val url: String)

data class AiClassifyResponse(
    val url: String,
    @param:JsonProperty("phishing_probability") val phishingProbability: Double,
    @param:JsonProperty("is_phishing") val isPhishing: Boolean,
)

@Component
class AiClassifyClient(private val aiRestClient: RestClient) {

    fun classify(url: String): AiClassifyResponse =
        aiRestClient
            .post()
            .uri("/classify")
            .contentType(MediaType.APPLICATION_JSON)
            .body(AiClassifyRequest(url))
            .retrieve()
            .body(AiClassifyResponse::class.java)!!
}
