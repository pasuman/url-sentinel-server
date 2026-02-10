package com.seheon99.urlsentinel.network

import com.seheon99.urlsentinel.config.NetworkFeaturesProperties
import org.apache.commons.net.whois.WhoisClient
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.Hashtable
import javax.naming.directory.InitialDirContext
import javax.net.ssl.HttpsURLConnection
import kotlin.system.measureTimeMillis

@Service
class NetworkFeaturesService(
    private val properties: NetworkFeaturesProperties,
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
        collectWhoisFeatures(parsedUrl, features)

        logger.debug("Collected network features for {}: {}", url, features)
        return features
    }

    private fun collectDnsFeatures(url: URL, features: MutableMap<String, Double>) {
        if (!properties.dns.enabled) {
            return
        }

        // Existing features: time_response, qty_ip_resolved
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

        // Phase 1: Advanced DNS features using JNDI
        try {
            val env = Hashtable<String, String>()
            env["java.naming.factory.initial"] = "com.sun.jndi.dns.DnsContextFactory"
            env["com.sun.jndi.dns.timeout.initial"] = properties.dns.timeout.toString()
            val ctx = InitialDirContext(env)

            if (properties.dns.spfEnabled) {
                features["domain_spf"] = checkSpfRecord(ctx, url.host)
            }
            if (properties.dns.mxEnabled) {
                features["qty_mx_servers"] = countMxRecords(ctx, url.host)
            }
            if (properties.dns.nsEnabled) {
                features["qty_nameservers"] = countNameservers(ctx, url.host)
            }
            if (properties.dns.ttlEnabled) {
                features["ttl_hostname"] = getDnsTtl(ctx, url.host)
            }

            ctx.close()
        } catch (e: Exception) {
            logger.debug("DNS advanced feature collection failed for {}: {}", url.host, e.message)
            // Individual features will default to -1.0 if not collected
        }
    }

    private fun checkSpfRecord(ctx: InitialDirContext, host: String): Double {
        return try {
            val attrs = ctx.getAttributes(host, arrayOf("TXT"))
            val txtRecords = attrs.get("TXT")
            if (txtRecords != null) {
                for (i in 0 until txtRecords.size()) {
                    val record = txtRecords.get(i).toString()
                    if (record.lowercase().startsWith("v=spf1")) {
                        return 1.0
                    }
                }
            }
            0.0
        } catch (e: Exception) {
            logger.debug("SPF record check failed for {}: {}", host, e.message)
            -1.0
        }
    }

    private fun countMxRecords(ctx: InitialDirContext, host: String): Double {
        return try {
            val attrs = ctx.getAttributes(host, arrayOf("MX"))
            val mxRecords = attrs.get("MX")
            mxRecords?.size()?.toDouble() ?: 0.0
        } catch (e: Exception) {
            logger.debug("MX record count failed for {}: {}", host, e.message)
            -1.0
        }
    }

    private fun countNameservers(ctx: InitialDirContext, host: String): Double {
        return try {
            val attrs = ctx.getAttributes(host, arrayOf("NS"))
            val nsRecords = attrs.get("NS")
            nsRecords?.size()?.toDouble() ?: 0.0
        } catch (e: Exception) {
            logger.debug("NS record count failed for {}: {}", host, e.message)
            -1.0
        }
    }

    private fun getDnsTtl(ctx: InitialDirContext, host: String): Double {
        return try {
            val attrs = ctx.getAttributes(host, arrayOf("A"))
            val aRecords = attrs.get("A")
            if (aRecords != null) {
                // Try to extract TTL from attributes
                // Note: TTL extraction may vary by JVM implementation
                val ttlAttr = attrs.get("ttl")
                if (ttlAttr != null) {
                    return ttlAttr.get().toString().toDoubleOrNull() ?: -1.0
                }
            }
            -1.0
        } catch (e: Exception) {
            logger.debug("TTL extraction failed for {}: {}", host, e.message)
            -1.0
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
                    // Simple HTTPS connection test to verify certificate validity
                    val connection = url.openConnection() as HttpsURLConnection
                    connection.connectTimeout = 10000
                    connection.readTimeout = 10000
                    connection.requestMethod = "HEAD"
                    connection.connect()
                    connection.disconnect()
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

        // Phase 2: URL shortener detection
        try {
            val parsedUrl = URL(url)
            val host = parsedUrl.host?.lowercase() ?: ""

            // Known URL shortener domains
            val shortenerDomains = setOf(
                "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd",
                "buff.ly", "adf.ly", "j.mp", "lnkd.in", "cutt.ly", "shorturl.at",
                "rebrand.ly", "bl.ink", "short.io", "tiny.cc", "clck.ru", "v.gd",
                "s.id", "0x0.st", "shortcm.li", "yourls.org", "bitly.com"
            )

            val isShortener = shortenerDomains.any { domain ->
                host == domain || host.endsWith(".$domain")
            }
            features["url_shortened"] = if (isShortener) 1.0 else 0.0
        } catch (e: Exception) {
            logger.debug("URL shortener detection failed for {}: {}", url, e.message)
            features["url_shortened"] = -1.0
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

    private fun collectWhoisFeatures(url: URL, features: MutableMap<String, Double>) {
        if (!properties.whois.enabled) {
            return
        }

        try {
            val whoisResponse = queryWhois(url.host)

            // Parse creation date
            val creationDate = parseWhoisDate(whoisResponse, "Creation Date", "Created On", "Registered On", "Registration Time")
            if (creationDate != null) {
                val daysAgo = ChronoUnit.DAYS.between(creationDate, LocalDate.now())
                features["time_domain_activation"] = daysAgo.toDouble()
            } else {
                features["time_domain_activation"] = -1.0
            }

            // Parse expiration date
            val expirationDate = parseWhoisDate(whoisResponse, "Expiration Date", "Expires On", "Registry Expiry Date", "Expiry Date")
            if (expirationDate != null) {
                val daysUntil = ChronoUnit.DAYS.between(LocalDate.now(), expirationDate)
                features["time_domain_expiration"] = daysUntil.toDouble()
            } else {
                features["time_domain_expiration"] = -1.0
            }
        } catch (e: Exception) {
            logger.debug("WHOIS lookup failed for {}: {}", url.host, e.message)
            features["time_domain_activation"] = -1.0
            features["time_domain_expiration"] = -1.0
        }
    }

    private fun queryWhois(domain: String): String {
        val client = WhoisClient()
        try {
            client.defaultTimeout = properties.whois.timeout
            client.connect(WhoisClient.DEFAULT_HOST)
            val result = client.query(domain)
            client.disconnect()
            return result
        } catch (e: Exception) {
            client.disconnect()
            throw e
        }
    }

    private fun parseWhoisDate(whoisData: String, vararg patterns: String): LocalDate? {
        // Try multiple field names and date formats
        val dateFormatters = listOf(
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd"),
            DateTimeFormatter.ofPattern("dd-MMM-yyyy"),
            DateTimeFormatter.ofPattern("dd/MM/yyyy"),
            DateTimeFormatter.ofPattern("yyyy/MM/dd")
        )

        for (pattern in patterns) {
            val regex = Regex("$pattern\\s*:\\s*(.+)", RegexOption.IGNORE_CASE)
            val match = regex.find(whoisData)
            if (match != null) {
                val dateStr = match.groupValues[1].trim().split(" ").firstOrNull() ?: continue
                for (formatter in dateFormatters) {
                    try {
                        return LocalDate.parse(dateStr, formatter)
                    } catch (e: Exception) {
                        // Try next formatter
                    }
                }
            }
        }
        return null
    }
}
