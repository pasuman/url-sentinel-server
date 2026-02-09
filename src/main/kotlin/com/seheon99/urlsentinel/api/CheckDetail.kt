package com.seheon99.urlsentinel.api

/**
 * Details of a single verification check.
 */
data class CheckDetail(
    val name: String,
    val passed: Boolean,
    val score: Int,
    val message: String
)
