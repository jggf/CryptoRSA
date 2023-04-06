package org.example;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Encrypt {

    public static String enc(String publicKeyHex) throws Exception {
        // TK en hexadecimal que queremos cifrar
        final String tkHex = "0123456789ABCDEF0123456789ABCDEF";
        System.out.println("TK : " + tkHex);
        // Convertir el TK en bytes
        byte[] tkBytes = Hex.decodeHex(tkHex);
        // Convertir la clave pública RSA en formato ASN.1 DER de 2048 bits a objeto PublicKey

        System.out.println("Public Key : " + publicKeyHex.substring(0, 512));

        BigInteger modulus = new BigInteger(publicKeyHex.substring(0, 512), 16);
        BigInteger exponent = new BigInteger(publicKeyHex.substring(512, 518), 16);

        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // crear fábrica de claves RSA
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedTkBytes = cipher.doFinal(tkBytes);
        String encryptedTkHex = Hex.encodeHexString(encryptedTkBytes);
        System.out.println("TK encriptada: " + encryptedTkHex);
        return encryptedTkHex;
    }

    public static String encPK(String publicKeyHex) throws Exception {
        // TK en hexadecimal que queremos cifrar
        final String tkHex = "0123456789ABCDEF0123456789ABCDEF";
        System.out.println("TK : " + tkHex);
        // Convertir el TK en bytes
        byte[] tkBytes = Hex.decodeHex(tkHex);
        // Convertir la clave pública RSA en formato ASN.1 DER de 2048 bits a objeto PublicKey

        System.out.println("Public Key : " + publicKeyHex);
        byte[] bytes = DatatypeConverter.parseHexBinary(publicKeyHex);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        // Encriptar la clave TK con la clave pública RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedTkBytes = cipher.doFinal(tkBytes);
        String encryptedTkHex = Hex.encodeHexString(encryptedTkBytes);
        System.out.println("TK encriptada: " + encryptedTkHex);
        return encryptedTkHex;
    }


}
