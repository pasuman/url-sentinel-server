package com.seheon99.urlpolice

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.boot.runApplication

@SpringBootApplication
@ConfigurationPropertiesScan
class UrlPoliceApplication

fun main(args: Array<String>) {
    runApplication<UrlPoliceApplication>(*args)
}
