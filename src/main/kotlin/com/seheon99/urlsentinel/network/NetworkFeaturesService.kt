package com.seheon99.urlsentinel.network

import com.seheon99.urlsentinel.config.NetworkFeaturesProperties
import com.seheon99.urlsentinel.ssl.SslCertificateService
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import kotlin.system.measureTimeMillis

@Service
class NetworkFeaturesService(
    private val properties: NetworkFeaturesProperties,
    private val sslCertificateService: SslCertificateService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    /**
     * Collects available network features for the given URL.
     * Returns empty map if globally disabled or if URL is invalid.
     * Individual feature failures default to -1.0.
     */
    fun collectFeatures(url: String): Map<String, Double> {
        if (!properties.enabled) {
            return emptyMap()
        }

        val parsedUrl = try {
            URL(url)
        } catch (e: Exception) {
            logger.debug("Invalid URL for feature collection: {}", e.message)
            return emptyMap()
        }

        val features = mutableMapOf<String, Double>()

        collectDnsFeatures(parsedUrl, features)
        collectSslFeatures(parsedUrl, features)
        collectHttpFeatures(url, features)

        logger.debug("Collected network features for {}: {}", url, features)
        return features
    }

    private fun collectDnsFeatures(url: URL, features: MutableMap<String, Double>) {
        if (!properties.dns.enabled) {
            return
        }

        try {
            val responseTime = measureTimeMillis {
                val addresses = InetAddress.getAllByName(url.host)
                features["qty_ip_resolved"] = addresses.size.toDouble()
            }
            features["time_response"] = responseTime.toDouble()
        } catch (e: Exception) {
            logger.debug("DNS lookup failed for {}: {}", url.host, e.message)
            features["time_response"] = -1.0
            features["qty_ip_resolved"] = -1.0
        }
    }

    private fun collectSslFeatures(url: URL, features: MutableMap<String, Double>) {
        if (!properties.ssl.enabled) {
            return
        }

        // 0 for HTTP, 1 for valid HTTPS certificate, -1 for error
        when (url.protocol) {
            "http" -> features["tls_ssl_certificate"] = 0.0
            "https" -> {
                try {
                    sslCertificateService.fetchCertificate(url.toString())
                    features["tls_ssl_certificate"] = 1.0
                } catch (e: Exception) {
                    logger.debug("SSL certificate fetch failed for {}: {}", url, e.message)
                    features["tls_ssl_certificate"] = -1.0
                }
            }
            else -> features["tls_ssl_certificate"] = -1.0
        }
    }

    private fun collectHttpFeatures(url: String, features: MutableMap<String, Double>) {
        if (!properties.http.enabled) {
            return
        }

        try {
            val redirectCount = countRedirects(url)
            features["qty_redirects"] = redirectCount.toDouble()
        } catch (e: Exception) {
            logger.debug("Redirect count failed for {}: {}", url, e.message)
            features["qty_redirects"] = -1.0
        }
    }

    /**
     * Counts the number of HTTP redirects by following the redirect chain.
     * Uses HEAD requests to minimize data transfer.
     * Returns the redirect count or throws an exception on failure.
     */
    private fun countRedirects(urlString: String): Int {
        var currentUrl = urlString
        var redirectCount = 0
        val visited = mutableSetOf<String>()

        while (redirectCount < properties.http.maxRedirects) {
            if (!visited.add(currentUrl)) {
                // Redirect loop detected
                logger.debug("Redirect loop detected at {}", currentUrl)
                break
            }

            val connection = URL(currentUrl).openConnection() as HttpURLConnection
            try {
                connection.requestMethod = "HEAD"
                connection.instanceFollowRedirects = false
                connection.connectTimeout = properties.http.connectTimeout
                connection.readTimeout = properties.http.readTimeout
                connection.connect()

                val responseCode = connection.responseCode
                if (responseCode in 300..399) {
                    val location = connection.getHeaderField("Location")
                    if (location.isNullOrBlank()) {
                        logger.debug("Redirect without Location header at {}", currentUrl)
                        break
                    }

                    // Handle relative URLs
                    currentUrl = if (location.startsWith("http")) {
                        location
                    } else {
                        val base = URL(currentUrl)
                        URL(base, location).toString()
                    }

                    redirectCount++
                } else {
                    // Final destination reached
                    break
                }
            } finally {
                connection.disconnect()
            }
        }

        return redirectCount
    }
}
