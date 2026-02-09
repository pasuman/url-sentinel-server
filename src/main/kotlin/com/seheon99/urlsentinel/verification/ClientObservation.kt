package com.seheon99.urlsentinel.verification

/**
 * Client-observed TLS connection metadata.
 * Collected by the Android client during HTTPS connection.
 *
 * @property certificateChain PEM-encoded X.509 certificates, leaf first
 * @property serverIp IP address the client connected to
 * @property serverAsn Autonomous System Number of the server IP (optional)
 * @property tlsProtocol TLS protocol version (e.g., "TLSv1.3", "TLSv1.2")
 * @property cipherSuite Negotiated cipher suite (e.g., "TLS_AES_128_GCM_SHA256")
 * @property alpnProtocol Application-Layer Protocol Negotiation result (e.g., "h2", "http/1.1", null)
 */
data class ClientObservation(
    val certificateChain: List<String>,
    val serverIp: String,
    val serverAsn: Int?,
    val tlsProtocol: String,
    val cipherSuite: String,
    val alpnProtocol: String?
)
