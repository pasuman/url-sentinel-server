package com.seheon99.urlsentinel.verification

import org.springframework.stereotype.Service
import java.net.InetAddress
import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSession

/**
 * Fetches server-side TLS connection metadata.
 * Establishes an HTTPS connection and extracts certificate, IP, protocol, cipher suite, etc.
 */
@Service
class ServerDataFetcher(
    private val asnLookupService: AsnLookupService
) {

    companion object {
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 10_000
    }

    /**
     * Fetches server-side TLS data by establishing an HTTPS connection.
     *
     * @param urlString Target URL
     * @return Server-side TLS observations
     * @throws IllegalArgumentException if URL is not HTTPS
     * @throws Exception if connection fails
     */
    fun fetch(urlString: String): ServerData {
        val url = URL(urlString)
        require(url.protocol == "https") { "URL must use HTTPS protocol" }

        val connection = url.openConnection() as HttpsURLConnection
        connection.connectTimeout = CONNECT_TIMEOUT_MS
        connection.readTimeout = READ_TIMEOUT_MS
        connection.requestMethod = "HEAD"

        try {
            connection.connect()
            val session: SSLSession = connection.sslSocketFactory.createSocket(
                url.host,
                url.port.takeIf { it != -1 } ?: 443
            ).use { socket ->
                (socket as javax.net.ssl.SSLSocket).apply {
                    startHandshake()
                }.session
            }

            val certificates = session.peerCertificates.map { it as X509Certificate }
            val leafCertificate = certificates.first()

            // Resolve IP
            val inetAddress = InetAddress.getByName(url.host)
            val serverIp = inetAddress.hostAddress

            // Lookup ASN (fail-open)
            val serverAsn = try {
                asnLookupService.lookupAsn(serverIp)
            } catch (e: Exception) {
                null
            }

            return ServerData(
                certificate = leafCertificate,
                certificateChain = certificates,
                serverIp = serverIp,
                serverAsn = serverAsn,
                tlsProtocol = session.protocol,
                cipherSuite = session.cipherSuite,
                alpnProtocol = try {
                    // ALPN protocol (Java 9+)
                    session.javaClass.getMethod("getApplicationProtocol")
                        .invoke(session) as String?
                } catch (e: Exception) {
                    null
                }
            )
        } finally {
            connection.disconnect()
        }
    }
}
