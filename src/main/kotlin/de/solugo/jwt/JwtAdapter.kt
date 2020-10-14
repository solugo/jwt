package de.solugo.jwt

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.deser.std.StdDeserializer
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.databind.ser.std.StdSerializer
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

open class JwtAdapter {

    private val delimiterChar = '.'
    private val delimiterByte = delimiterChar.toByte()

    protected val encoder = Base64.getUrlEncoder().withoutPadding()
    protected val decoder = Base64.getUrlDecoder()
    protected val mapper = createMapper()

    fun encode(jwt: Jwt) = Context(
        headerData = jwt.header,
        headerValue = encoder.encodeToString(mapper.writeValueAsBytes(jwt.header)),
        bodyData = jwt.body,
        bodyValue = encoder.encodeToString(mapper.writeValueAsBytes(jwt.body)),
    ).let {
        it.copy(signatureValue = createSignature(it))
    }.run {
        "$headerValue.$bodyValue${signatureValue?.let { "$delimiterChar$it" } ?: ""}"
    }

    fun decode(value: String) = value.split(delimiterChar).let {
        Context(
            headerValue = if (it.size > 1) it[0] else null,
            bodyValue = if (it.size > 1) it[1] else it[0],
            signatureValue = if (it.size > 2) it[it.size - 1] else null,
        )
    }.also {
        if (!validateSignature(it)) error("Signature is invalid")
    }.let {
        val parser = mapper.createParser(decoder.decode(it.headerValue))
        if (parser.nextToken() != JsonToken.START_OBJECT) error("Header is not a json object")

        val data = hashMapOf<String, Any?>()
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            val name = parser.text
            val type = resolveHeaderType(it, name)
            parser.nextToken()
            data[name] = mapper.readValue(parser, type)
        }

        it.copy(
            headerData = data.toMap()
        )
    }.let {
        val parser = mapper.createParser(decoder.decode(it.bodyValue))
        if (parser.nextToken() != JsonToken.START_OBJECT) error("Body is not a json object")

        val data = hashMapOf<String, Any?>()
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            val name = parser.text
            val type = resolveBodyType(it, name)
            parser.nextToken()
            data[name] = mapper.readValue(parser, type)
        }

        it.copy(
            bodyData = data.toMap()
        )
    }.let {
        Jwt(
            header = it.headerData ?: emptyMap(),
            body = it.bodyData ?: emptyMap(),
        )
    }

    protected open fun createMapper() = ObjectMapper().apply {
        registerModule(SimpleModule("ZonedDateTime").apply {
            addSerializer(
                ZonedDateTime::class.java,
                object : StdSerializer<ZonedDateTime>(ZonedDateTime::class.java) {
                    override fun serialize(
                        value: ZonedDateTime,
                        generator: JsonGenerator,
                        provider: SerializerProvider
                    ) {
                        generator.writeNumber(value.toInstant().epochSecond)
                    }
                }
            )
            addDeserializer(
                ZonedDateTime::class.java,
                object : StdDeserializer<ZonedDateTime>(ZonedDateTime::class.java) {
                    override fun deserialize(
                        parser: JsonParser,
                        ctxt: DeserializationContext
                    ): ZonedDateTime {
                        return Instant.ofEpochSecond(parser.nextLongValue(0)).atZone(ZoneId.systemDefault())
                    }
                }
            )
        })
    }

    protected open fun resolveHeaderType(context: Context, name: String): Class<*> = when (name) {
        "alg" -> String::class.java
        "typ" -> String::class.java
        "cty" -> String::class.java
        "key" -> String::class.java
        else -> Any::class.java
    }

    protected open fun resolveBodyType(context: Context, name: String): Class<*> = when (name) {
        "iss" -> String::class.java
        "sub" -> String::class.java
        "aud" -> String::class.java
        "jti" -> String::class.java
        "exp" -> ZonedDateTime::class.java
        "nbf" -> ZonedDateTime::class.java
        else -> Any::class.java
    }

    protected open fun createSignature(context: Context): String? = null
    protected open fun validateSignature(context: Context): Boolean = true

    protected fun createHmacSignature(context: Context, secret: ByteArray): String {
        val algorithm = mapAlgorithm(context.headerData?.get("alg")?.toString() ?: "HMAC256")
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(secret, algorithm))
        mac.update(context.headerValue?.encodeToByteArray())
        mac.update(delimiterByte)
        mac.update(context.bodyValue?.encodeToByteArray())

        return encoder.encodeToString(mac.doFinal())
    }

    protected fun createRsaSignature(context: Context, key: RSAPrivateKey): String {
        val algorithm = context.headerData?.get("alg")?.toString() ?: "RSA256"
        val signature = Signature.getInstance(
            when (algorithm) {
                "RSA256" -> "SHA256withRSA"
                "RSA384" -> "SHA384withRSA"
                "RSA512" -> "SHA512withRSA"
                else -> algorithm
            }
        )
        signature.initSign(key)
        signature.update(context.headerValue?.encodeToByteArray())
        signature.update(delimiterByte)
        signature.update(context.bodyValue?.encodeToByteArray())

        return encoder.encodeToString(signature.sign())
    }

    protected fun createEcSignature(context: Context, key: ECPrivateKey): String {
        val algorithm = mapAlgorithm(context.headerData?.get("alg")?.toString() ?: "ES256")
        val signature = Signature.getInstance(algorithm)
        signature.initSign(key)
        signature.update(context.headerValue?.encodeToByteArray())
        signature.update(delimiterByte)
        signature.update(context.bodyValue?.encodeToByteArray())

        return encoder.encodeToString(signature.sign())
    }

    protected fun validateHmacSignature(context: Context, secret: ByteArray): Boolean {
        return context.signatureValue == createHmacSignature(context, secret)
    }

    protected fun validateRsaSignature(context: Context, key: RSAPublicKey): Boolean {
        val algorithm = mapAlgorithm(context.headerData?.get("alg")?.toString() ?: "RSA256")
        val signature = Signature.getInstance(algorithm)
        signature.initVerify(key)
        signature.update(context.headerValue?.encodeToByteArray())
        signature.update(delimiterByte)
        signature.update(context.bodyValue?.encodeToByteArray())
        return signature.verify(decoder.decode(context.signatureValue))
    }

    protected fun validateEcSignature(context: Context, key: ECPublicKey): Boolean {
        val algorithm = mapAlgorithm(context.headerData?.get("alg")?.toString() ?: "ES256")
        val signature = Signature.getInstance(algorithm)
        signature.initVerify(key)
        signature.update(context.headerValue?.encodeToByteArray())
        signature.update(delimiterByte)
        signature.update(context.bodyValue?.encodeToByteArray())
        return signature.verify(decoder.decode(context.signatureValue))
    }

    protected open fun mapAlgorithm(value: String) = when (value) {
        "HMAC256" -> "HmacSHA256"
        "HMAC384" -> "HmacSHA384"
        "HMAC512" -> "HmacSHA512"
        "RSA256" -> "SHA256withRSA"
        "RSA384" -> "SHA384withRSA"
        "RSA512" -> "SHA512withRSA"
        "EC256" -> "SHA256withEC"
        "EC384" -> "SHA384withEC"
        "EC512" -> "SHA512withEC"
        else -> error("Algorithm $value is not supported")
    }

    data class Context(
        val headerValue: String? = null,
        val headerData: Map<String, Any?>? = null,
        val bodyValue: String? = null,
        val bodyData: Map<String, Any?>? = null,
        val signatureValue: String? = null,
    )

}