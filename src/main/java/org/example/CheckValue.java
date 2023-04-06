package org.example;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class CheckValue {


    public static String checkValue(byte[] encryptedSymmetricKey) throws NoSuchAlgorithmException {
        // Generar un checksum de la clave simétrica encriptada
        byte[] checksum = generateChecksum(encryptedSymmetricKey);
        // Codificar el checksum en Base64 y truncarlo a 6 caracteres
        return truncateBase64(Base64.getEncoder().encodeToString(checksum), 6);
    }

    // Método para generar un checksum de una clave simétrica encriptada
    private static byte[] generateChecksum(byte[] encryptedSymmetricKey) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(encryptedSymmetricKey);
    }

    // Método para truncar una cadena Base64 a un número determinado de caracteres
    private static String truncateBase64(String base64, int length) {
        if (base64.length() <= length) {
            return base64;
        } else {
            return base64.substring(0, length);
        }
    }

}
