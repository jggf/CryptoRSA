package org.example;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) throws Exception {
        // Generar una clave aleatoria TK
        SecureRandom secureRandom = new SecureRandom();
        byte[] tkBytes = new byte[32];
        secureRandom.nextBytes(tkBytes);
        String tk = Hex.encodeHexString(tkBytes);
        System.out.println("TK: " + tk);

        // Convertir la clave pública RSA en formato ASN.1 DER de 2048 bits a objeto PublicKey
        String publicKeyHex = "CF41C5307C06CEDEB52983CFA1DE0E2F397BC87970C14AB2EF0822739E6D64B89BF5717055F600420FC442A9E2E0C96AC62C27ED6C864BEDCAC119B7A469D3541532B660B4CB0ABA8C0D3CEAFD44D0F73C8C95D02E69DF6FD438C9D4092ACEDE830C3E8CABC7C3D2C7544963073738BA340C7C20240772BDCE9315DA070FA774C3C6B5050E21B02A594BA4E5EBCB3908E864AED79F9231B18D02152F255955D3D10CA006C18E9CD768E6137469A45BB82DFF1D9C8E095D467EC9150AC38AB84743D21AC1D82D310BC421D26A4B8901CE879E0B6F5DA981BEBCEDD0C17F39DB57DCEF68B1B574BDF8C817D209660D8145735C1899AFEE41C795E1CE46901ABADB03010001";

        byte[] publicKeyBytes = Hex.decodeHex(publicKeyHex); // convertir a bytes

        BigInteger modulus = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 0, 256));
        BigInteger exponent = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 256, 512));

        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // crear fábrica de claves RSA
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // Encriptar la clave TK con la clave pública RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedTkBytes = cipher.doFinal(tkBytes);
        String encryptedTkHex = Hex.encodeHexString(encryptedTkBytes);

        System.out.println("TK encriptada: " + encryptedTkHex);
    }

    public static void metodAux(String publicKeyHex) throws Exception {

        // La clave pública RSA en formato ASN.1 DER en hexadecimal
        publicKeyHex = publicKeyHex.replaceAll("[^0-9A-Fa-f]", "");

        // Convertir la clave pública en un objeto PublicKey de Java
        byte[] publicKeyBytes = Hex.decodeHex(publicKeyHex);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // TK en hexadecimal que queremos cifrar
        String tkHex = "1234567890abcdef1234567890abcdef";

        // Convertir el TK en bytes
        byte[] tkBytes = Hex.decodeHex(tkHex);

        // Cifrar el TK con la clave pública RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedTkBytes = cipher.doFinal(tkBytes);

        // Convertir el TK cifrado en hexadecimal
        String encryptedTkHex = Hex.encodeHexString(encryptedTkBytes);
        System.out.println("TK cifrado: " + encryptedTkHex);
    }
}