package com.seheon99.urlsentinel.verification

import java.security.cert.X509Certificate

/**
 * Server-side TLS connection data fetched by the URL Sentinel server.
 *
 * @property certificate Server's X.509 certificate (leaf)
 * @property certificateChain Full certificate chain from server
 * @property serverIp Resolved IP address
 * @property serverAsn Autonomous System Number of the resolved IP
 * @property tlsProtocol Negotiated TLS protocol version
 * @property cipherSuite Negotiated cipher suite
 * @property alpnProtocol ALPN negotiation result
 */
data class ServerData(
    val certificate: X509Certificate,
    val certificateChain: List<X509Certificate>,
    val serverIp: String,
    val serverAsn: Int?,
    val tlsProtocol: String?,
    val cipherSuite: String?,
    val alpnProtocol: String?
)
