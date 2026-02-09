package com.seheon99.urlsentinel.verification

import org.springframework.stereotype.Service
import java.security.cert.X509Certificate

/**
 * Service for checking Certificate Transparency (CT) log presence.
 * Checks for the SCT (Signed Certificate Timestamp) extension in certificates.
 */
@Service
class CertificateTransparencyService {

    companion object {
        // OID for SCT extension: 1.3.6.1.4.1.11129.2.4.2
        private const val SCT_EXTENSION_OID = "1.3.6.1.4.1.11129.2.4.2"
    }

    /**
     * Checks if a certificate has a CT log entry (SCT extension).
     *
     * @param certificate X.509 certificate to check
     * @return true if SCT extension is present, false otherwise
     */
    fun hasCertificateTransparency(certificate: X509Certificate): Boolean {
        return try {
            val sctExtension = certificate.getExtensionValue(SCT_EXTENSION_OID)
            sctExtension != null && sctExtension.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }
}
