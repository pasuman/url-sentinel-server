package com.seheon99.urlpolice.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.client.RestClient

@Configuration
class AiClientConfig {

    @Bean
    fun aiRestClient(properties: AiProperties): RestClient =
        RestClient.builder().baseUrl(properties.baseUrl).build()
}
