package org.example;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) {
        try {
            crearLlaves();
            String tkEn = enc("30820122300D06092A864886F70D01010105000382010F003082010A0282010100A60E84E800DEB78EC988D36C1A369FB08E5A28293F57114A340B54734AA37F1EFA35A184E9CBA581074F7871D9BB349686C947D2A731B47510CE26B5BC7A3641E59ABDBB1532B6EAD795790FB3234BF68C2304F104466437D54325D80093698BFDA0B5545517E4310B3D67D5A70A388B05749CB8B3914FC21B49624E9226A5189AF9439431E0D59829C22CB6D538E3F2539E050760DD0A0F76CD55404474A3A4DD530B22EA7AE5D15157750936CE204BB988B3EEC0F37ADB74FE35AB263FC37B00B9BC84AF94EF71B234B89AB6CC7E149535B8048AB48E2FBEF6DE4943E123CB48B8EF607AE75FC39784CDB63AFE38902CF3D8574FDA19560EDAD03A07978D610203010001");
            des("308204BE020100300D06092A864886F70D0101010500048204A8308204A40201000282010100A60E84E800DEB78EC988D36C1A369FB08E5A28293F57114A340B54734AA37F1EFA35A184E9CBA581074F7871D9BB349686C947D2A731B47510CE26B5BC7A3641E59ABDBB1532B6EAD795790FB3234BF68C2304F104466437D54325D80093698BFDA0B5545517E4310B3D67D5A70A388B05749CB8B3914FC21B49624E9226A5189AF9439431E0D59829C22CB6D538E3F2539E050760DD0A0F76CD55404474A3A4DD530B22EA7AE5D15157750936CE204BB988B3EEC0F37ADB74FE35AB263FC37B00B9BC84AF94EF71B234B89AB6CC7E149535B8048AB48E2FBEF6DE4943E123CB48B8EF607AE75FC39784CDB63AFE38902CF3D8574FDA19560EDAD03A07978D61020301000102820101009D8DA7128D48C37669C7357A1B00FAD0C4AFCBED1ED8D861C4317FC607EA4A81B4BACFEE50F954A5B0AEF943646757C4FE4BD9A687D604371263D69C96208A7C49826144311FB627E9B63B6FE6F2B56F4E95276A1A39437B2A1014C6F5FCE7A6D854F3D6F909BB0BC17358A2816394346B4FB22718D0E590F0DCD6B65FBAE4E67D5876A6B4D285C59060D5679FFF79E69ECE3116C3042E807992DF419A2DBD7A019CA4E1038A8D8C1C672075D7A9279D93C883D237F0DB9C6C762DA79D865B8CF879132552A6474788F3881D159DD9E2D258F137503B8954C8E53F5C0E45E74FBEE0963F95B1F3EC2FF067A3291739BC89052D8F4CDAABF2798717399F96916502818100FC5717445283B77382D4970C5D322C760A77405C6A68EBB3108DBCCC5A9DA94CBD41DE3928C5F1E82AC8921D60FA8CE01B210F6F09383E72B8DAE4AEE3C6C6E8AF4FF73170110548B14DEA47A0378ADB44140B62873D066BAC9A84D66FAE9A33614B6504D9065C1180CCBEDEA6F5E6E0F34652A07B9AEFCED3B6DDFD020DB14302818100A87711670A868B7858A10AC187DC1F5EA3EDA0EEADCD07090CD788DB07CD4DE99437BBBDF0044CB31B569B7ECBB0BD9CD6056DC18DC8676E45A1A1449B70FDB5EAF0C5FA686D7D570D2640C33C9C67684868977977A433A443433290F4604BB10024158DAEDFC8F7447A25E84B60C2EFAEA8E9BA103828F5A181F37659029A8B028180200FD4C5FA91FFD22E72628AD0A09A63992AD3C3AA4590851CFA555DC5B9B894268BE2F77245CC59CA6DD79AE20293B9B9D8B6844E309646AF5428B04C02AAAD4FF1222066F3D2AF0CD0308F4F3D1F6882BAE5436C99856252F9031DD7ECE06CDCD4DE8E02213BBB8199023B7A0D4E7B908D83DC1E386E75E2129F1C1191B9CF0281803C5497C8DCFE1E087545070313D282F173A77010C9F138E9C6CD91574F4DF8EF03838A1A955014DFB794A68F1C072980772CEE87786D228D5D266B0894DA3C21E00765FF2D52B8A66A311ED44C6A7EA5DBF888F6992016D666B833EDB176A2E4BA7631B9D1BC96CDE69A0FE546C95A4657B86A2B960F66ABC0B1372D54E717CD02818100D91DF2E07C30776250D7C04B456AC3AB3912A248D9052A2424DE0D3F262081C30BFF6F4ECD413DB01E9F0114E53DC98A1AF9C2CD825B457FF8F9B179D38AC756D11F76EF26F1BB163215071EC2BEDA524EE77B1C7498F14B1262E9703EA61E589B44BDA61A66A4F2D2C72E96C75FB55B14705737465B06E1591A9B21293730EF", tkEn);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

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
            String privateKeyHex = bytesToHex(privateKeyBytes);
            String publicKeyHex = bytesToHex(publicKeyBytes);

            // Imprimir resultados
            System.out.println("Private Key:");
            System.out.println(privateKeyHex);

            System.out.println("Public Key:");
            System.out.println(publicKeyHex.substring(29, 541)); // Mostrar solo los 512 caracteres del modulo
            System.out.println(publicKeyHex);
            System.out.println(publicKey.getPublicExponent());


        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error: " + e.getMessage());
        }

    }

    // Convertir un arreglo de bytes a su representación hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }


//    public static void m1() {
//        try {
//            // Convertir la clave pública RSA en formato ASN.1 DER de 2048 bits a objeto PublicKey
//            String publicKeyHex = "1010105000382010F003082010A02820101008F4EF63F7949C9BF6D05379BB1059B1753EBADDA2744E618B51858EAA176B636E8E9BDEA431A2155099A5AF6FF1AF5A887DEA58A5CF1A1B288F47CA1F93D87176AA047695917F8E4D612DF422D5F51D49F71390B3EE4CC73AC5B53DB3B4EBCCFE010D9791632788E910A066ADF74DF5E3B632E1E5421574683231DFCD0A7B2C49E81B9CCAA8C44FEC7047026AC5269B2B96F280F1C5A01B734DAB8756CB804F644137C8A325332BD87BAA56D13DF7C05D7C1CBA6FA25CBE6829FCA22B30B15A658501BDFAC7369550723643F54E769CF7EEB9C7C5134211617D1037A9596F22E6FFCAD98DB0F437FC7553488E763635353337";
//            byte[] publicKeyBytes = Hex.decodeHex(publicKeyHex); // convertir a bytes
//            BigInteger modulus = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 0, 256));
//            BigInteger exponent = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 256, 512));
//
//            System.out.println(modulus);
//            System.out.println(exponent);
//
//
//        } catch (DecoderException e) {
//            throw new RuntimeException(e);
//        }
//
//    }

    public static String enc(String publicKeyHex) throws Exception {
        // TK en hexadecimal que queremos cifrar
        final String tkHex = "0123456789ABCDEF0123456789ABCDEF";
        System.out.println("TK : " + tkHex);
        // Convertir el TK en bytes
        byte[] tkBytes = Hex.decodeHex(tkHex);
        // Convertir la clave pública RSA en formato ASN.1 DER de 2048 bits a objeto PublicKey

        System.out.println("Public Key : " + publicKeyHex);
        byte[] publicKeyBytes = Hex.decodeHex(publicKeyHex); // convertir a bytes


        BigInteger modulus = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 0, 256));
        BigInteger exponent = new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 256, 259));

        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // crear fábrica de claves RSA
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        // Encriptar la clave TK con la clave pública RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedTkBytes = cipher.doFinal(tkBytes);
        String encryptedTkHex = Hex.encodeHexString(encryptedTkBytes);
        System.out.println("TK encriptada: " + encryptedTkHex);
        return encryptedTkHex;
    }

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


//    public static void metodAux(String publicKeyHex) throws Exception {
//
//        // La clave pública RSA en formato ASN.1 DER en hexadecimal
//        publicKeyHex = publicKeyHex.replaceAll("[^0-9A-Fa-f]", "");
//
//        // Convertir la clave pública en un objeto PublicKey de Java
//        byte[] publicKeyBytes = Hex.decodeHex(publicKeyHex);
//        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
//
//        // TK en hexadecimal que queremos cifrar
//        String tkHex = "1234567890abcdef1234567890abcdef";
//
//        // Convertir el TK en bytes
//        byte[] tkBytes = Hex.decodeHex(tkHex);
//
//        // Cifrar el TK con la clave pública RSA
//        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] encryptedTkBytes = cipher.doFinal(tkBytes);
//
//        // Convertir el TK cifrado en hexadecimal
//        String encryptedTkHex = Hex.encodeHexString(encryptedTkBytes);
//        System.out.println("TK cifrado: " + encryptedTkHex);
//    }
}