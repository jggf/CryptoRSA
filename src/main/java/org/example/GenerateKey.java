package org.example;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class GenerateKey {

    public static void crearLlaves() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();

            byte[] privateKeyBytes = privateKey.getEncoded();

            byte[] publicKeyBytes = publicKey.getEncoded();

            // Convertir a formato hexadecimal

            // Imprimir resultados
            System.out.println("Private Key:");
            System.out.println(DatatypeConverter.printHexBinary(privateKeyBytes));


            System.out.println("Public Key:");
            System.out.println(DatatypeConverter.printHexBinary(publicKeyBytes));
            System.out.println(publicKey.getModulus().toString(16));
            System.out.println(DatatypeConverter.printHexBinary(publicKey.getPublicExponent().toByteArray()));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

}
