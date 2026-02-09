package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.ssl.SslCertificateService
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/ssl")
class SslVerifyController(
    private val sslCertificateService: SslCertificateService,
) {

    @PostMapping("/verify")
    fun verify(@RequestBody request: SslVerifyRequest): SslVerifyResponse {
        require(request.url.isNotBlank()) { "URL must not be blank" }

        return sslCertificateService.verifyCertificate(request.url, request.clientFingerprint)
    }
}
