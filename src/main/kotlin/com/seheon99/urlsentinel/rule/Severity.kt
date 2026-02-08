package com.seheon99.urlsentinel.rule

enum class Severity(val weight: Int) {
    CRITICAL(40),
    MAJOR(20),
    MINOR(10),
}
