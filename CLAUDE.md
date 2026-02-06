# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Spring Boot 4.0 REST API server for the URL Police Android application.

- **Spring Boot 4.0** on **Spring Framework 7.0**
- **Java 17+** required (compatible up to Java 25)
- **Gradle 8.14+** or 9.x (Kotlin DSL)
- **Language**: Kotlin

## Build & Run Commands

- **Build**: `./gradlew build`
- **Run**: `./gradlew bootRun`
- **Test all**: `./gradlew test`
- **Test single class**: `./gradlew test --tests "com.example.ClassName"`
- **Test single method**: `./gradlew test --tests "com.example.ClassName.methodName"`
- **Clean build**: `./gradlew clean build`

## Architecture

- **API style**: REST, serving an Android client
- Spring Boot plugin: `org.springframework.boot`
- Dependency management: `io.spring.dependency-management`
- Snapshot repo required: `https://repo.spring.io/snapshot`

## MCP rules

- Always use Context7 MCP when I need library/API documentation, code generation, setup or configuration steps without me having to explicitly ask.
