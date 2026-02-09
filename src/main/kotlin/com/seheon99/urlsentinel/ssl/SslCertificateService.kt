package com.seheon99.urlsentinel.ssl

import com.seheon99.urlsentinel.api.CertificateDetails
import com.seheon99.urlsentinel.api.SslVerdict
import com.seheon99.urlsentinel.api.SslVerifyResponse
import com.seheon99.urlsentinel.config.SslProperties
import org.springframework.stereotype.Service
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException
import javax.net.ssl.SSLPeerUnverifiedException

@Service
class SslCertificateService(
    private val sslProperties: SslProperties,
) {
    fun verifyCertificate(url: String, clientFingerprint: String): SslVerifyResponse {
        // Validate URL protocol
        val parsedUrl = try {
            URL(url)
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid URL format: ${e.message}")
        }

        if (parsedUrl.protocol != "https") {
            throw IllegalArgumentException("URL must use HTTPS protocol")
        }

        // Validate fingerprint format (64 hex chars with optional colons)
        val normalizedClientFp = normalizeFingerprint(clientFingerprint)
        if (!normalizedClientFp.matches(Regex("^[0-9A-F]{64}$"))) {
            throw IllegalArgumentException("Invalid fingerprint format. Expected 64 hexadecimal characters.")
        }

        return try {
            val certificate = fetchCertificate(url)
            val serverFingerprint = computeFingerprint(certificate)
            val normalizedServerFp = normalizeFingerprint(serverFingerprint)
            val certificateDetails = extractCertificateDetails(certificate)

            if (normalizedClientFp == normalizedServerFp) {
                SslVerifyResponse(
                    verdict = SslVerdict.MATCH,
                    serverFingerprint = serverFingerprint,
                    clientFingerprint = clientFingerprint,
                    certificateDetails = certificateDetails,
                    message = "Certificate fingerprints match. Connection is secure."
                )
            } else {
                SslVerifyResponse(
                    verdict = SslVerdict.MISMATCH,
                    serverFingerprint = serverFingerprint,
                    clientFingerprint = clientFingerprint,
                    certificateDetails = certificateDetails,
                    message = "Certificate fingerprints do not match. Possible DNS hijacking or MITM attack."
                )
            }
        } catch (e: UnknownHostException) {
            SslVerifyResponse(
                verdict = SslVerdict.ERROR,
                serverFingerprint = null,
                clientFingerprint = clientFingerprint,
                certificateDetails = null,
                message = "Unable to resolve hostname"
            )
        } catch (e: ConnectException) {
            SslVerifyResponse(
                verdict = SslVerdict.ERROR,
                serverFingerprint = null,
                clientFingerprint = clientFingerprint,
                certificateDetails = null,
                message = "Unable to connect to server"
            )
        } catch (e: SocketTimeoutException) {
            SslVerifyResponse(
                verdict = SslVerdict.ERROR,
                serverFingerprint = null,
                clientFingerprint = clientFingerprint,
                certificateDetails = null,
                message = "Connection timeout"
            )
        } catch (e: SSLPeerUnverifiedException) {
            SslVerifyResponse(
                verdict = SslVerdict.ERROR,
                serverFingerprint = null,
                clientFingerprint = clientFingerprint,
                certificateDetails = null,
                message = "Server certificate not verified"
            )
        } catch (e: SSLException) {
            SslVerifyResponse(
                verdict = SslVerdict.ERROR,
                serverFingerprint = null,
                clientFingerprint = clientFingerprint,
                certificateDetails = null,
                message = "SSL handshake failed"
            )
        } catch (e: Exception) {
            SslVerifyResponse(
                verdict = SslVerdict.ERROR,
                serverFingerprint = null,
                clientFingerprint = clientFingerprint,
                certificateDetails = null,
                message = "Unable to verify certificate: ${e.message}"
            )
        }
    }

    fun fetchCertificate(url: String): X509Certificate {
        val parsedUrl = URL(url)

        if (parsedUrl.protocol != "https") {
            throw IllegalArgumentException("URL must use HTTPS protocol")
        }

        var connection: HttpsURLConnection? = null
        try {
            connection = parsedUrl.openConnection() as HttpsURLConnection
            connection.connectTimeout = sslProperties.connectTimeout
            connection.readTimeout = sslProperties.readTimeout
            connection.instanceFollowRedirects = false
            connection.connect()

            val certificates = connection.serverCertificates
            if (certificates.isEmpty()) {
                throw SSLException("No certificates received from server")
            }

            // Return the leaf certificate (server's own certificate)
            return certificates[0] as X509Certificate
        } finally {
            connection?.disconnect()
        }
    }

    fun computeFingerprint(certificate: X509Certificate): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(certificate.encoded)

        // Format as hex string with colons (e.g., "A1:B2:C3:...")
        return hash.joinToString(":") { byte ->
            "%02X".format(byte)
        }
    }

    fun extractCertificateDetails(certificate: X509Certificate): CertificateDetails {
        val formatter = DateTimeFormatter.ISO_INSTANT
        val validFrom = certificate.notBefore.toInstant().atZone(ZoneId.of("UTC")).format(formatter)
        val validTo = certificate.notAfter.toInstant().atZone(ZoneId.of("UTC")).format(formatter)
        val isExpired = certificate.notAfter.toInstant().isBefore(Instant.now())

        return CertificateDetails(
            subject = certificate.subjectX500Principal.name,
            issuer = certificate.issuerX500Principal.name,
            validFrom = validFrom,
            validTo = validTo,
            isExpired = isExpired
        )
    }

    fun normalizeFingerprint(fingerprint: String): String {
        // Remove colons and spaces, convert to uppercase
        return fingerprint.replace(":", "").replace(" ", "").uppercase()
    }
}
