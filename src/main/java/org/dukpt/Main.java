package org.dukpt;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class Main {

   private static final String input =
         "5413330002001171D141220106464048FFFFFF654FFFFFFF42353137373132363233373031343539315E434C49454E54452F454C202020202020202020202020202020205E31343031313031303030303030303030303030303030373031303030303030FFFFFFFF";

   private static final String KEY_ENCRYPTED = "65C455EACA6EE1D4C05ECDA3CEDD99C6";

   private static String KSN = "0020100008fff1000000".toUpperCase();

   private static String incrementKSN(String initialKSN, String increment) {

      BigInteger hexaValue = new BigInteger(initialKSN, 16); // Convert from hexadecimal to BigInteger
      BigInteger incrementValue = new BigInteger(increment, 16); // Convert increment to BigInteger
      hexaValue = hexaValue.add(incrementValue); // Incremet KSN in hexa
      return StringUtils.leftPad(hexaValue.toString(16), 20, "0").toUpperCase();
   }

   public static void main22(String[] args) {

      String blocks = "5413330002001171";
      //String[] blocks = getBlocks();

      System.out.println("Antes de encriptar");
      System.out.println(blocks);

      final byte[] ksn = Hex.decode(KSN);

      final byte[] bdk = Hex.decode(KEY_ENCRYPTED);

      try {
         final byte[] sessionKey = diversifyKey2(new SecretKeySpec(bdk, "DESede"), ksn);
         //final byte[] sessionKey = Hex.decode("9B12B5555BE0B56047A173B432672310");
         //final byte[] sessionKey = "10AB93B59352E946B0844FC22ED1DE34".getBytes(StandardCharsets.UTF_8);
         //final byte[] sessionKey = Dukpt.computeKey(bdk, ksn);

         System.out.println("Llave diversificada : " + Hex.toHexString(sessionKey));

         System.out.println("Despues de encriptar");
         final String sf10 = encryptTracks(sessionKey, blocks);



         System.out.println(sf10);
         System.out.println("Despues de desencriptar");
         System.out.println(Hex.toHexString(Dukpt.decryptDes(sessionKey, Hex.decode(sf10))));

      } catch (Exception e) {
         e.printStackTrace();
      }

   }

   public static void main11(String[] args) {
      System.out.println(KSN);
      String ksn = KSN;
      for (int i = 0; i < 20; i++) {
         //ksn = updateKSN(ksn);
         ksn = incrementKSN(ksn, "001");
         System.out.println(ksn);
      }

   }

   private static String updateKSN(String ksn) {
      //KSN - Transaction Counter - Ecounter
      BigInteger ecounter = new BigInteger(ksn, 16);
      ecounter = ecounter.add(BigInteger.ONE);
      ksn = ecounter.toString(16).toUpperCase();
      return ksn;
   }

   public static void main(String[] args) {

      final byte[] ksn = DatatypeConverter.parseHexBinary(KSN);

      final byte[] bdk = DatatypeConverter.parseHexBinary(KEY_ENCRYPTED);

      try {

         byte[] key_1 = Dukpt.computeKey(bdk, ksn);
         //byte[] key_2 = diversifyKey2(new SecretKeySpec(bdk, "DESede"), ksn);

         System.out.println(Hex.toHexString(key_1));
         //System.out.println(Hex.toHexString(key_2));

         System.out.println(Hex.toHexString(Dukpt.decryptDes(key_1, key_1)));

      } catch (Exception e) {
         e.printStackTrace();
      }
   }

   public static void main33(String[] args) {

      String[] blocks = input.split("(?<=\\G.{16})");
      //String[] blocks = getBlocks();

      System.out.println("Antes de encriptar");
      for (String block : blocks) {
         System.out.println(block);
      }
      final byte[] ksn = Hex.decode(KSN);

      final byte[] bdk = Hex.decode(KEY_ENCRYPTED);

      try {
         //final byte[] sessionKey = diversifyKey(new SecretKeySpec(bdk, "DESede"), ksn);
         final byte[] sessionKey = Hex.decode("10AB93B59352E946B0844FC22ED1DE34");
         //final byte[] sessionKey = "10AB93B59352E946B0844FC22ED1DE34".getBytes(StandardCharsets.UTF_8);
         //final byte[] sessionKey = Dukpt.computeKey(bdk, ksn);

         System.out.println("Llave diversificada : " + Hex.toHexString(sessionKey));

         System.out.println("Despues de encriptar");
         String[] blockEncrypt = encryptTracks(sessionKey, blocks);

         final String sf10 = Arrays.stream(blockEncrypt, 0, 3).collect(Collectors.joining()).toUpperCase();

         System.out.println(sf10);
         System.out.println("Despues de desencriptar");
         System.out.println(Hex.toHexString(Dukpt.decryptDes(sessionKey, Hex.decode(sf10))));

      } catch (Exception e) {
         e.printStackTrace();
      }

   }

   private static byte[] decryptData(byte[] encryptedData, SecretKey key) {
      // Set up the counter mode parameters
      byte[] iv = new byte[8];
      ParametersWithIV params = new ParametersWithIV(new KeyParameter(key.getEncoded()), iv);

      // Create a DES engine and initialize it with the key
      DESEngine engine = new DESEngine();
      engine.init(false, params);

      // Decrypt the data using the DES engine and the counter mode
      byte[] decryptedData = new byte[encryptedData.length];
      engine.processBlock(encryptedData, 0, decryptedData, 0);
      return decryptedData;
   }


   public static String[] getBlocks() {
      final String[] blocks = new String[13];
      final String str = input;
      final AtomicInteger part = new AtomicInteger(0);
      IntStream.range(0, 13).forEach(index -> blocks[index] = str.substring(part.intValue(), part.addAndGet(16)));
      return blocks;
   }

   private static byte[] diversifyKey(final SecretKey bdk, final byte[] ksn) {
      final byte[] ipek = deriveIPEK(bdk, ksn);
      System.out.println(Hex.toHexString(ipek));
      final byte[] divKeyBytes = new byte[16];
      System.arraycopy(ipek, 0, divKeyBytes, 0, 8);
      System.arraycopy(ipek, 0, divKeyBytes, 8, 8);
      System.out.println(Hex.toHexString(divKeyBytes));
      return divKeyBytes;
   }

   private static final int BLOCK_SIZE = 16;

   private static byte[] diversifyKey2(final SecretKey bdk, final byte[] ksn) {
      // obtener el IV a partir del KSN
      byte[] iv = new byte[BLOCK_SIZE];
      System.arraycopy(ksn, 0, iv, 0, 16);
      iv[BLOCK_SIZE - 1] &= 0xFE;
      IvParameterSpec ivSpec = new IvParameterSpec(iv);

      // cifrar el IV con la clave BDK
      try {
         javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DESede/CBC/NoPadding");
         cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, bdk, ivSpec);
         byte[] diversificationData = cipher.doFinal(new byte[BLOCK_SIZE]);

         // construir la clave diversificada
         byte[] diversifiedKey = new byte[BLOCK_SIZE * 2];
         System.arraycopy(diversificationData, 0, diversifiedKey, 0, BLOCK_SIZE);
         System.arraycopy(diversificationData, 0, diversifiedKey, BLOCK_SIZE, BLOCK_SIZE);
         return diversifiedKey;
      } catch (Exception e) {
         throw new RuntimeException("Error al diversificar la clave", e);
      }
   }

   private static byte[] deriveIPEK(final SecretKey bdk, final byte[] ksn) {
      final byte[] keyData = new byte[16];
      final byte[] ksnData = new byte[10];
      System.arraycopy(bdk.getEncoded(), 0, keyData, 0, 16);
      System.arraycopy(ksn, 0, ksnData, 0, 10);
      final byte[] data = new byte[16];
      data[0] = (byte) 0xC0;
      System.arraycopy(keyData, 0, data, 1, 8);
      System.arraycopy(ksnData, 0, data, 9, 6);

      final byte[] iv = new byte[16];
      new SecureRandom().nextBytes(iv);
      final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

      try {
         // Install Bouncy Castle provider
         Security.addProvider(new BouncyCastleProvider());

         final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
         cipher.init(Cipher.ENCRYPT_MODE, bdk, ivParameterSpec);

         for (int i = 0; i < 3; i++) {
            final byte[] result = cipher.doFinal(data);
            for (int j = 0; j < 16; j++) {
               keyData[j] ^= result[j];
            }
            data[0]++;
         }
         final byte[] ipek = new byte[16];
         System.arraycopy(keyData, 0, ipek, 0, 16);
         return ipek;
      } catch (final GeneralSecurityException ex) {
         System.out.println(ex.getMessage());
         return null;
      }
   }

   private static String[] encryptTracks(final byte[] keyBytes, final String[] blocks) {
      final String[] cipheredBlocks = new String[blocks.length];
      final BlockCipher engine = new DESedeEngine();
      final BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(engine));
      final AtomicInteger index = new AtomicInteger(1);
      Arrays.stream(blocks).map(block -> decodeHex(block.toCharArray())).forEach(block -> {
         try {
            cipher.init(true, new org.bouncycastle.crypto.params.DESedeParameters(keyBytes));
            final int len = block.length;
            final byte[] ciphertext = new byte[cipher.getOutputSize(len)];
            final int outputLength = cipher.processBytes(block, 0, len, ciphertext, 0);
            cipher.doFinal(ciphertext, outputLength);
            final String blockCipheredCommon = DatatypeConverter.printHexBinary(ciphertext);
            cipheredBlocks[index.getAndIncrement() - 1] = blockCipheredCommon;
         } catch (final InvalidCipherTextException ex) {
            System.out.println(ex.getMessage());
         }
      });
      return cipheredBlocks;
   }

   private static String encryptTracks(final byte[] keyBytes, final String blocks) {
      final String[] cipheredBlocks = new String[1];
      final BlockCipher engine = new DESedeEngine();
      final BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(engine));
      final AtomicInteger index = new AtomicInteger(1);
      //Arrays.stream(blocks).map(block -> decodeHex(block.toCharArray())).forEach(block -> {
      Stream.of(decodeHex(blocks.toCharArray())).forEach(block -> {
         try {
            cipher.init(true, new org.bouncycastle.crypto.params.DESedeParameters(keyBytes));
            final int len = block.length;
            final byte[] ciphertext = new byte[cipher.getOutputSize(len)];
            final int outputLength = cipher.processBytes(block, 0, len, ciphertext, 0);
            cipher.doFinal(ciphertext, outputLength);
            final String blockCipheredCommon = DatatypeConverter.printHexBinary(ciphertext);
            cipheredBlocks[index.getAndIncrement() - 1] = blockCipheredCommon;
         } catch (final InvalidCipherTextException ex) {
            System.out.println(ex.getMessage());
         }
      });
      return cipheredBlocks[0];
   }

   private static byte[] decodeHex(final char[] value) {
      try {
         return org.apache.commons.codec.binary.Hex.decodeHex(value);
      } catch (final DecoderException ex) {
         System.out.println(ex.getMessage());
         return null;
      }
   }
}
