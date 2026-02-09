package com.seheon99.urlsentinel.verification

import org.springframework.stereotype.Service
import org.springframework.web.client.RestClient
import org.springframework.web.client.body
import java.time.Duration

/**
 * Service for looking up Autonomous System Numbers (ASN) for IP addresses.
 * Uses the ipapi.co free API.
 */
@Service
class AsnLookupService {

    private val restClient = RestClient.builder()
        .baseUrl("https://ipapi.co")
        .build()

    companion object {
        private val TIMEOUT = Duration.ofSeconds(3)
    }

    /**
     * Looks up the ASN for an IP address.
     *
     * @param ip IP address (IPv4 or IPv6)
     * @return ASN number, or null if lookup fails
     */
    fun lookupAsn(ip: String): Int? {
        return try {
            val response = restClient.get()
                .uri("/$ip/json/")
                .retrieve()
                .body<IpapiResponse>()

            response?.asn?.removePrefix("AS")?.toIntOrNull()
        } catch (e: Exception) {
            // Fail-open: return null on any error
            null
        }
    }

    private data class IpapiResponse(
        val asn: String?
    )
}
