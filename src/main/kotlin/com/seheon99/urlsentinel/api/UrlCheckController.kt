package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.rule.RuleEngine
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/url")
class UrlCheckController(
    private val ruleEngine: RuleEngine,
) {

    @PostMapping("/check")
    fun check(@RequestBody request: UrlCheckRequest): UrlCheckResponse {
        require(request.url.isNotBlank()) { "URL must not be blank" }
        return ruleEngine.evaluate(request.url)
    }
}
