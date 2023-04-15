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

   private static final String KEY_ENCRYPTED = "00112233445566778899AABBCCDDEEFF";

   private static String KSN = "0102012345678AE00002".toUpperCase();

   private static String incrementKSN(String initialKSN, String increment) {

      BigInteger hexaValue = new BigInteger(initialKSN, 16); // Convert from hexadecimal to BigInteger
      BigInteger incrementValue = new BigInteger(increment, 16); // Convert increment to BigInteger
      hexaValue = hexaValue.add(incrementValue); // Incremet KSN in hexa
      return StringUtils.leftPad(hexaValue.toString(16), 20, "0").toUpperCase();
   }

   public static void main(String[] args) {

      String blocks = "5413330002001171";
      //String[] blocks = getBlocks();
      System.out.println("KSN");
      System.out.println(KSN);
      System.out.println("BDK");
      System.out.println(KEY_ENCRYPTED);
      System.out.println("Antes de encriptar");
      System.out.println(blocks);

      final byte[] ksn = Hex.decode(KSN);

      final byte[] bdk = Hex.decode(KEY_ENCRYPTED);

      try {
         byte[] derivedKey = Dukpt.computeKey(bdk, ksn);
         byte[] sessionKey = Dukpt.toDataKey(derivedKey);

         System.out.println("Llave diversificada");
         System.out.println(Hex.toHexString(sessionKey));

         System.out.println("Despues de encriptar");
         final String sf10 = encryptTracks(sessionKey, blocks);

         System.out.println(sf10);
         System.out.println("Despues de desencriptar");
         byte[] decryptedPayload = Dukpt.decryptTripleDes(sessionKey, Dukpt.toByteArray(sf10));
         System.out.println(Dukpt.toHex(decryptedPayload));

      } catch (Exception e) {
         e.printStackTrace();
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
