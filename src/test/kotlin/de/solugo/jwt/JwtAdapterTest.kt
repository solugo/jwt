package de.solugo.jwt

import org.junit.jupiter.api.Test

class JwtAdapterTest {

    @Test
    fun encode() {
        val adapter = CustomAdapter()
        val value = adapter.encode(Jwt(body = mapOf("dta" to Data())))

        println(value)
    }

    @Test
    fun decode() {
        val adapter = CustomAdapter()
        val jwt = adapter.decode(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJkdGEiOnsidmFsdWUiOiJCbGEifX0.jajtNbkN0SjJ0k-R1Y8o_OXVPKyN3dO_cImTFy-x9kw"
        )
        println(jwt)
    }

    class CustomAdapter : JwtAdapter() {
        override fun resolveBodyType(context: Context, name: String) = when (name) {
            "dta" -> Data::class.java
            else -> super.resolveBodyType(context, name)
        }

        override fun validateSignature(context: Context) = validateHmacSignature(context, "secret".encodeToByteArray())
    }

    data class Data(
        val value: String = "Bla"
    )
}