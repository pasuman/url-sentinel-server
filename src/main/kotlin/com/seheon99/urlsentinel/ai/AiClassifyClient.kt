package com.seheon99.urlsentinel.ai

import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient

data class AiClassifyRequest(
    val url: String,
    @param:JsonProperty("network_features") val networkFeatures: Map<String, Double>? = null,
)

data class AiClassifyResponse(
    val url: String,
    @param:JsonProperty("phishing_probability") val phishingProbability: Double,
    @param:JsonProperty("is_phishing") val isPhishing: Boolean,
)

@Component
class AiClassifyClient(private val aiRestClient: RestClient) {

    fun classify(url: String, networkFeatures: Map<String, Double>? = null): AiClassifyResponse =
        aiRestClient
            .post()
            .uri("/classify")
            .contentType(MediaType.APPLICATION_JSON)
            .body(AiClassifyRequest(url, networkFeatures))
            .retrieve()
            .body(AiClassifyResponse::class.java)!!
}
