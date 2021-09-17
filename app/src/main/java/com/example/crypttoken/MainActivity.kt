package com.example.crypttoken

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import com.example.crypttoken.databinding.ActivityMainBinding
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers
import org.jose4j.jwk.EcJwkGenerator
import org.jose4j.jwk.EllipticCurveJsonWebKey
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.InvalidJwtException
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.EllipticCurves

class MainActivity : AppCompatActivity() {
    private val TAG = MainActivity::class.qualifiedName
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.fab.setOnClickListener { view ->
            cryptData()
        }
    }

    private fun cryptData() {
        val senderKeys: EllipticCurveJsonWebKey = EcJwkGenerator.generateJwk(EllipticCurves.P256)
        senderKeys.keyId = "sender's key"

        val receiverKeys: EllipticCurveJsonWebKey = EcJwkGenerator.generateJwk(EllipticCurves.P256)
        receiverKeys.keyId = "receiver's key"

        val applicationDataClaimName = "applicationData"

        val claims = JwtClaims()

        claims.setClaim(applicationDataClaimName, "tokenV2 data") // applicationData

        val jws = JsonWebSignature()
        jws.payload = claims.toJson()

        jws.key = senderKeys.privateKey
        jws.keyIdHeaderValue = senderKeys.keyId
        jws.algorithmHeaderValue =
            AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256 // Elliptic curve digital signature algorithm

        val innerJwt = jws.compactSerialization // applicationData + signature
        Log.i(TAG, "signed application data: $innerJwt")

        val jwe = JsonWebEncryption()
        jwe.algorithmHeaderValue =
            KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW // Elliptic Curve Diffie-Hellman Ephemeral Static
        jwe.encryptionMethodHeaderParameter =
            ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256

        jwe.key = receiverKeys.publicKey
        jwe.keyIdHeaderValue = receiverKeys.keyId
        jwe.contentTypeHeaderValue = "JWT"
        jwe.payload = innerJwt
        val jwt = jwe.compactSerialization // applicationData + signature encrypted

        Log.i(TAG, "crypted application data: $jwt")

        // client

        val jwtConsumer = JwtConsumerBuilder()
            .setDecryptionKey(receiverKeys.privateKey) // decrypt with the receiver's private key
            .setVerificationKey(senderKeys.publicKey) // verify the signature with the sender's public key
            .build()

        try {
            val jwtClaims = jwtConsumer.processToClaims(jwt)
            val applicationData = jwtClaims.getClaimValueAsString(applicationDataClaimName)
            Log.i(TAG, "decrypted application data : $applicationData") // application data decrypted and signature validated
        } catch (e: InvalidJwtException) {
            // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
            // Hopefully with meaningful explanations(s) about what went wrong.
            Log.i(TAG, "Invalid JWT! $e")
        }
    }
}