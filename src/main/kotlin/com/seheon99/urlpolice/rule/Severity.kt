package com.seheon99.urlpolice.rule

enum class Severity(val weight: Int) {
    CRITICAL(40),
    MAJOR(20),
    MINOR(10),
}
