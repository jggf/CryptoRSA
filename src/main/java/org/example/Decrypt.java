package org.example;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class Decrypt {

    public static void des(String privateKeyHex, String encryptedTkHex) throws Exception {
        // Convertir la clave privada RSA en formato ASN.1 DER de 2048 bits a objeto PrivateKey
        byte[] privateKeyBytes = Hex.decodeHex(privateKeyHex); // convertir a bytes
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // crear fábrica de claves RSA
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Desencriptar la clave TK con la clave privada RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedTkBytes = Hex.decodeHex(encryptedTkHex);
        byte[] tkBytes = cipher.doFinal(encryptedTkBytes);
        String tkHex = Hex.encodeHexString(tkBytes);
        System.out.println("TK desencriptada: " + tkHex);
    }
}
