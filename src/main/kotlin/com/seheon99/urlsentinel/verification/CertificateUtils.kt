package com.seheon99.urlsentinel.verification

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Utility functions for certificate parsing and analysis.
 */
object CertificateUtils {

    private val certificateFactory = CertificateFactory.getInstance("X.509")

    /**
     * Parses a PEM-encoded certificate string into an X509Certificate.
     *
     * @param pem PEM-encoded certificate (with or without BEGIN/END markers)
     * @return Parsed X509Certificate
     * @throws IllegalArgumentException if the PEM string is invalid
     */
    fun parsePem(pem: String): X509Certificate {
        val cleanPem = pem.trim()
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("\\s".toRegex(), "")

        val decoded = java.util.Base64.getDecoder().decode(cleanPem)
        return certificateFactory.generateCertificate(ByteArrayInputStream(decoded)) as X509Certificate
    }

    /**
     * Extracts the Subject Public Key Info (SPKI) from a certificate.
     * SPKI is the unique identifier for a public key including algorithm and parameters.
     *
     * @param certificate X509 certificate
     * @return SPKI as byte array
     */
    fun extractSpki(certificate: X509Certificate): ByteArray {
        return certificate.publicKey.encoded
    }

    /**
     * Computes SHA-256 fingerprint of a byte array.
     *
     * @param data Input bytes
     * @return Hex-encoded SHA-256 hash
     */
    fun sha256Fingerprint(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(data)
        return hash.joinToString("") { "%02x".format(it) }
    }

    /**
     * Validates a certificate chain against the system trust store.
     *
     * @param chain Certificate chain to validate (leaf first)
     * @param hostname Expected hostname for certificate validation
     * @return true if the chain is valid and trusted, false otherwise
     */
    fun validateChain(chain: List<X509Certificate>, hostname: String): Boolean {
        return try {
            val validator = java.security.cert.CertPathValidator.getInstance("PKIX")
            val certPath = certificateFactory.generateCertPath(chain)

            val trustManagerFactory = javax.net.ssl.TrustManagerFactory.getInstance(
                javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()
            )
            trustManagerFactory.init(null as java.security.KeyStore?)

            val trustManagers = trustManagerFactory.trustManagers
            val x509TrustManager = trustManagers.first { it is javax.net.ssl.X509TrustManager }
                as javax.net.ssl.X509TrustManager

            // Validate chain against system trust anchors
            val trustAnchors = x509TrustManager.acceptedIssuers.map {
                java.security.cert.TrustAnchor(it, null)
            }.toSet()

            val params = java.security.cert.PKIXParameters(trustAnchors)
            params.isRevocationEnabled = false // Disable OCSP for simplicity

            validator.validate(certPath, params)

            // Validate hostname
            val hostnameVerifier = javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier()
            val session = object : javax.net.ssl.SSLSession {
                override fun getPeerCertificates() = chain.toTypedArray()
                override fun getId() = ByteArray(0)
                override fun getSessionContext() = null
                override fun getCreationTime() = 0L
                override fun getLastAccessedTime() = 0L
                override fun invalidate() {}
                override fun isValid() = true
                override fun putValue(name: String, value: Any) {}
                override fun getValue(name: String) = null
                override fun removeValue(name: String) {}
                override fun getValueNames() = emptyArray<String>()
                override fun getLocalCertificates() = null
                override fun getLocalPrincipal() = null
                override fun getPeerPrincipal() = chain.first().subjectX500Principal
                override fun getCipherSuite() = ""
                override fun getProtocol() = ""
                override fun getPeerHost() = hostname
                override fun getPeerPort() = 443
                override fun getPacketBufferSize() = 0
                override fun getApplicationBufferSize() = 0
            }

            hostnameVerifier.verify(hostname, session)
        } catch (e: Exception) {
            false
        }
    }
}
