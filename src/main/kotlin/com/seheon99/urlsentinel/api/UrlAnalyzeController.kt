package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.rule.RuleEngine
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
class UrlAnalyzeController(
    private val ruleEngine: RuleEngine
) {

    @PostMapping("/analyze")
    fun analyze(@RequestBody request: UrlAnalyzeRequest): UrlAnalyzeResponse {
        require(request.url.isNotBlank()) { "URL must not be blank" }

        val result = ruleEngine.evaluate(request.url)

        return UrlAnalyzeResponse(
            verdict = result.verdict,
            reasons = result.reasons,
            riskScore = result.riskScore
        )
    }
}
