package com.seheon99.urlsentinel.adapter

/**
 * AI Adapter: Interface to external AI service for phishing classification.
 *
 * This adapter abstracts communication with the AI service (FastAPI + LightGBM),
 * allowing the Sentinel Server to integrate with external ML models without
 * tight coupling.
 */
interface AiAdapter {
    /**
     * Classifies a URL using the AI model.
     *
     * @param url The URL to classify
     * @param networkFeatures Optional network features for enhanced detection
     * @return Classification result with probability and verdict
     */
    fun classify(url: String, networkFeatures: Map<String, Double>? = null): AiClassificationResult
}

/**
 * Result of AI classification.
 */
data class AiClassificationResult(
    val url: String,
    val phishingProbability: Double,
    val isPhishing: Boolean,
)
