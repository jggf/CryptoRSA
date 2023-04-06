package org.example;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Arrays;

public class RSAEncryptionExample {

    public static void main(String[] args) throws Exception {

        // Generar un par de claves RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Obtener la clave pública y privada
        PublicKey publicKey = keyPair.getPublic();

        PrivateKey privateKey = keyPair.getPrivate();

        // TK en hexadecimal que queremos cifrar
        final String tkHex = "0123456789ABCDEF0123456789ABCDEF";
        System.out.println("Antes de encriptar : " + tkHex);
        // Convertir el TK en bytes
        byte[] tkBytes = Hex.decodeHex(tkHex);

        // Encriptar la clave TK con la clave pública RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedTkBytes = cipher.doFinal(tkBytes);
        String encryptedTkHex = Hex.encodeHexString(encryptedTkBytes);
        System.out.println("TK encriptada: " + encryptedTkHex);

        // Desencriptar la clave TK con la clave privada RSA
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedTkBytes = cipher.doFinal(encryptedTkBytes);
        String decryptedTkHex = Hex.encodeHexString(decryptedTkBytes);
        System.out.println("TK desencriptada: " + decryptedTkHex);
        System.out.println(tkHex.equalsIgnoreCase(decryptedTkHex) ? "Clave coincide" : "Error en desincriptar");
        // Verificar que la clave TK original y la desencriptada sean iguales
        if (Arrays.equals(tkBytes, decryptedTkBytes)) {
            System.out.println("La clave TK original y la desencriptada son iguales");
        } else {
            System.out.println("La clave TK original y la desencriptada son diferentes");
        }
    }
}