package org.dukpt;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class AlgoritmoBDK {

   private static final String BDK = "00112233445566778899AABBCCDDEEFF";
   private static final String KSN = "01020123456789E00000";
   private static final String XOR_KEY = "C0C0C0C000000000C0C0C0C000000000";

   public static void main(String[] args) throws Exception {
      String derivedKey = calculateDerivedKey();
      System.out.println("Derived Key: " + derivedKey);
   }

   private static String calculateDerivedKey() throws Exception {
      // Step 1: Calculate Initial Encryption Key (IKey)
      String iKey = calculateInitialKey();

      // Step 2: XOR BDK with XOR_KEY
      byte[] bdkBytes = hexStringToByteArray(BDK);
      byte[] xorKeyBytes = hexStringToByteArray(XOR_KEY);
      for (int i = 0; i < 16; i++) {
         bdkBytes[i] ^= xorKeyBytes[i];
      }

      // Step 3: Calculate Right Half of IKey
      String rightIKey = calculateTripleDes(iKey.substring(16), hexByteArrayToString(bdkBytes));
      return iKey.substring(0, 16) + rightIKey;
   }

   private static String calculateInitialKey() throws Exception {
      // Step 1: Calculate CA
      String ca = KSN.substring(0, 16);

      // Step 2: Calculate Serial Number from CA
      byte[] caBytes = hexStringToByteArray(ca);
      byte[] serialNumberBytes = new byte[1];
      serialNumberBytes[0] = (byte) (caBytes[7] & 0xE0);
      String serialNumber = hexByteArrayToString(serialNumberBytes);

      // Step 3: Calculate Left Half of IKey
      String leftIKey = calculateTripleDes(serialNumber, ca);

      return leftIKey + leftIKey;
   }

   private static String calculateTripleDes(String key, String input) throws Exception {
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      byte[] keyBytes = md.digest(key.getBytes(StandardCharsets.UTF_8));
      DESedeKeySpec spec = new DESedeKeySpec(keyBytes);
      SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
      SecretKey desKey = keyFactory.generateSecret(spec);
      Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, desKey);
      byte[] encrypted = cipher.doFinal(hexStringToByteArray(input));
      return hexByteArrayToString(encrypted);
   }

   private static byte[] hexStringToByteArray(String s) {
      int len = s.length();
      byte[] data = new byte[len / 2];
      for (int i = 0; i < len; i += 2) {
         data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
               + Character.digit(s.charAt(i+1), 16));
      }
      return data;
   }

   private static String hexByteArrayToString(  byte[] bytes) {
      StringBuilder sb = new StringBuilder();
      for (byte b : bytes) {
         sb.append(String.format("%02X", b));
      }
      return sb.toString();
   }
}