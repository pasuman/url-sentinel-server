package com.seheon99.urlsentinel

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.boot.runApplication

@SpringBootApplication
@ConfigurationPropertiesScan
class UrlSentinelApplication

fun main(args: Array<String>) {
    runApplication<UrlSentinelApplication>(*args)
}
