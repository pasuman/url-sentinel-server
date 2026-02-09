package com.seheon99.urlsentinel.adapter

import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient

/**
 * REST-based AI Adapter implementation.
 *
 * Communicates with the AI service via HTTP REST API.
 * Sends URL and optional network features, receives phishing probability.
 */
@Component
class RestAiAdapter(
    private val aiRestClient: RestClient,
) : AiAdapter {

    override fun classify(url: String, networkFeatures: Map<String, Double>?): AiClassificationResult {
        val response = aiRestClient
            .post()
            .uri("/classify")
            .contentType(MediaType.APPLICATION_JSON)
            .body(AiClassifyRequest(url, networkFeatures))
            .retrieve()
            .body(AiClassifyResponse::class.java)!!

        return AiClassificationResult(
            url = response.url,
            phishingProbability = response.phishingProbability,
            isPhishing = response.isPhishing,
        )
    }

    // Internal DTOs for REST communication
    private data class AiClassifyRequest(
        val url: String,
        @param:JsonProperty("network_features") val networkFeatures: Map<String, Double>? = null,
    )

    private data class AiClassifyResponse(
        val url: String,
        @param:JsonProperty("phishing_probability") val phishingProbability: Double,
        @param:JsonProperty("is_phishing") val isPhishing: Boolean,
    )
}
