package com.rodkrtz.krypto

import org.bouncycastle.asn1.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory

class PKCS12(
    private val byteArray: ByteArray,
    private val pass: String
) {

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    companion object {
        const val FORMAT = "PKCS12"

        val oidOwnerName = ASN1ObjectIdentifier("2.16.76.1.3.2")
        val oidOwnerCnpj = ASN1ObjectIdentifier("2.16.76.1.3.3")
        val oidOwnerCpf = ASN1ObjectIdentifier("2.16.76.1.3.1")
    }

    val keyStore: KeyStore by lazy {
        try {
            KeyStore.getInstance(FORMAT, BouncyCastleProvider.PROVIDER_NAME)
                .apply { load(byteArray.inputStream(), pass.toCharArray()) }
        } catch (e: Exception) {
            try {
                KeyStore.getInstance(FORMAT)
                    .apply { load(byteArray.inputStream(), pass.toCharArray()) }
            } catch (e: Exception) {
                throw IllegalStateException("An error occurred while loading the keystore", e)
            }
        }
    }

    val keyManagers: Array<KeyManager> by lazy {
        val ksf = KeyManagerFactory.getInstance("SunX509")
        ksf.init(keyStore, pass.toCharArray())
        ksf.keyManagers
    }

    val ownerCertificate: X509Certificate by lazy {
        keyStore.aliases()
            .asSequence()
            .map { keyStore.getCertificate(it) as X509Certificate }
            .firstOrNull { it.basicConstraints < 0 }
            ?: error("Owner certificate not found")
    }

    val ownerName: String by lazy {
        val asn1Object = getASN1Object(oidOwnerName)
            ?: error("Owner name not found")

        asn1ObjectToString(asn1Object)
    }

    val ownerDocument: String by lazy {
        val asn1Object = getASN1Object(oidOwnerCnpj)
            ?: getASN1Object(oidOwnerCpf)
            ?: error("Owner document not found")

        asn1ObjectToString(asn1Object)
    }

    private val asn1Sequences: List<ASN1Sequence> by lazy {
        ownerCertificate.subjectAlternativeNames
            .asSequence()
            .filterIsInstance<List<*>>()
            .mapNotNull { it[1] as? ByteArray }
            .map { ASN1Sequence.fromByteArray(it) }
            .mapNotNull { it as? DLTaggedObject }
            .mapNotNull { it.baseObject as? ASN1Sequence }
            .toList()
    }

    private fun getASN1Object(objectIdentifier: ASN1ObjectIdentifier): ASN1Object? {
        return asn1Sequences
            .filter { it.getObjectAt(0) as ASN1ObjectIdentifier == objectIdentifier }
            .firstNotNullOfOrNull { it.getObjectAt(1) as? ASN1TaggedObject }
            ?.baseObject
    }

    private fun asn1ObjectToString(o: ASN1Object): String {
        return when (o) {
            is DEROctetString -> String(o.octets)
            is DERPrintableString -> o.string
            is DERUTF8String -> o.string
            else -> error("There is no treatment for this type of object [${o::class.java}]")
        }
    }
}