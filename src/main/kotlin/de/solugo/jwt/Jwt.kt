package de.solugo.jwt

data class Jwt (
    val header: Map<String, Any?> = emptyMap(),
    val body: Map<String, Any?> = emptyMap(),
)