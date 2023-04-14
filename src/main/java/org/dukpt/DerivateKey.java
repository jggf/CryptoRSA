package org.dukpt;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class DerivateKey {

   public static void main(String[] args) throws Exception {
      // Datos de entrada
      String ksn = "01020123456789E00000";
      String bdk = "00112233445566778899AABBCCDDEEFF";

      // Cálculo de la llave de encripción inicial
      byte[] ca = hexStringToByteArray(ksn.substring(0, 16));
      byte[] ca8 = new byte[]{ca[7]};
      byte[] ca8AndE0 = new byte[]{(byte) (ca[7] & 0xE0)};
      byte[] caInitial = new byte[8];



      System.arraycopy(ca, 0, caInitial, 0, 8);

      SecretKeySpec initialKey = new SecretKeySpec(tripleDesEncrypt(caInitial, bdk), "DESede");
      byte[] leftIkey = tripleDesEncrypt(caInitial, toHexString(initialKey.getEncoded()));

      byte[] xorBytes = hexStringToByteArray("C0C0C0C000000000C0C0C0C000000000");
      byte[] rightIkey = tripleDesEncrypt(caInitial, toHexString(xorByteArray(ca8AndE0, xorBytes)));

      byte[] ikey = new byte[16];
      System.arraycopy(leftIkey, 0, ikey, 0, 8);
      System.arraycopy(rightIkey, 0, ikey, 8, 8);
      String ikeyString = toHexString(ikey);

      // Cálculo de la derivada de clave de sesión (SDD)
      String ksnLeft = ksn.substring(0, 15) + "0";
      String ksnRight = "0000" + ksn.substring(15, 16);

      byte[] sdd = tripleDesEncrypt(hexStringToByteArray(ksnLeft + ksnRight), ikeyString);
      String sddString = toHexString(sdd);
      System.out.println(sddString);
   }

   public static byte[] xorByteArray(byte[] a, byte[] b) {
      byte[] result = new byte[a.length];
      for (int i = 0; i < result.length; i++) {
         result[i] = (byte) (a[i] ^ b[i]);
      }
      return result;
   }

   public static byte[] tripleDesEncrypt(byte[] data, String key) throws Exception {
      byte[] keyBytes = hexStringToByteArray(key);
      SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DESede");
      Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, keySpec);
      return cipher.doFinal(data);
   }

   public static byte[] hexStringToByteArray(String s) {
      int len = s.length();
      byte[] data = new byte[len / 2];
      for (int i = 0; i < len; i += 2) {
         data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
      }
      return data;
   }

   public static String toHexString(byte[] data) {
      StringBuilder sb = new StringBuilder();
      for (byte b : data) {
         sb.append(String.format("%02X", b));
      }
      return sb.toString();
   }
}

