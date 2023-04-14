package org.dukpt;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class DerivationExample {

   public static void main(String[] args) throws Exception {
      // BDK y KSN
      byte[] bdk = hexStringToByteArray("00112233445566778899AABBCCDDEEFF");
      byte[] ksn = hexStringToByteArray("01020123456789E00000");

      // Cálculo de la llave de encripción inicial
      byte[] ca = Arrays.copyOfRange(ksn, 0, 8);
      ca[7] &= (byte) 0xE0;
      byte serNum = (byte) (ca[7] & 0xFF);
      byte[] caKey = Arrays.copyOf(ca, 8);
      byte[] leftKey = performTripleDes(caKey, hexStringToByteArray("C0C0C0C000000000C0C0C0C000000000"));
      byte[] iKey = new byte[16];
      System.arraycopy(leftKey, 0, iKey, 0, 8);
      System.arraycopy(leftKey, 0, iKey, 8, 8);
      byte[] curKey = Arrays.copyOf(iKey, iKey.length);

      // Copiar el KSNR en R8
      byte[] r8 = Arrays.copyOf(ksn, ksn.length);

      // Clarear los 21 bits de más a la derecha de R8
      r8[r8.length - 3] &= 0x1F;
      r8[r8.length - 2] = 0;
      r8[r8.length - 1] = 0;

      // Copiar los 21 bits de más a la derecha del KSNR en R3
      byte[] r3 = Arrays.copyOf(ksn, ksn.length);
      r3[0] &= 0x1F;
      r3[1] = 0;
      r3[2] = 0;

      // Encender el bit de más a la izquierda de SR, clarear los otros 20 bits
      byte[] sr = new byte[3];
      sr[0] = (byte) 0x80;
      sr[1] = 0;
      sr[2] = 0;

      // Realizar Triple DES de R8 con la variación de la llave inicial y guardar en la mitad izquierda de Curkey
      byte[] rightKey = performTripleDes(caKey, r8);
      System.arraycopy(rightKey, 0, curKey, 0, 8);

      // Realizar operación XOR con la BDK y el hexadecimal C0C0C0C000000000C0C0C0C000000000
      byte[] xorBytes = hexStringToByteArray("C0C0C0C000000000C0C0C0C000000000");
      for (int i = 0; i < 16; i++) {
         curKey[i] ^= bdk[i] ^ xorBytes[i];
      }

      // Realizar TRIPLE DES de CA con la variación de la llave inicial y guardar el resultado en la mitad derecha de Curkey
      byte[] rightKey2 = performTripleDes(caKey, r3);
      System.arraycopy(rightKey2, 0, curKey, 8, 8);

      // Imprimir la derivada resultante
      String derivada = byteArrayToHexString(curKey);
      System.out.println(derivada);
   }

   public static byte[] performTripleDes(byte[] key, byte[] data) throws Exception {
      SecretKeySpec keySpec = new SecretKeySpec(key, "DESede");
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

   public static String byteArrayToHexString(byte[] bytes) {
      StringBuilder sb = new StringBuilder();
      for (byte b : bytes) {
         sb.append(String.format("%02X", b));
      }
      return sb.toString();
   }
}
