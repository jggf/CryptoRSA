package org.dukpt;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.util.Arrays;

public final class Dukpt {
   public static final int NUM_OVERWRITES = 3;

   public static final String KEY_REGISTER_BITMASK = "C0C0C0C000000000C0C0C0C000000000";
   private static final BitSet DEFAULT_KEY_REGISTER_BITMASK = toBitSet(toByteArray(KEY_REGISTER_BITMASK));

   public static final String DATA_VARIANT_BITMASK = "0000000000FF00000000000000FF0000";
   public static final String MAC_VARIANT_BITMASK  = "000000000000FF00000000000000FF00";
   public static final String PIN_VARIANT_BITMASK  = "00000000000000FF00000000000000FF";
   private static final BitSet DEFAULT_VARIANT_BITMASK = toBitSet(toByteArray(PIN_VARIANT_BITMASK));

   public static byte[] computeKey(byte[] baseDerivationKey, byte[] keySerialNumber) throws Exception {
      BitSet bitSetKSN = Dukpt.toBitSet(Dukpt.toByteArray(Dukpt.KEY_REGISTER_BITMASK));
      BitSet bitSetBDK = Dukpt.toBitSet(Dukpt.toByteArray(Dukpt.DATA_VARIANT_BITMASK));

      return computeKey(baseDerivationKey, keySerialNumber, bitSetKSN, bitSetBDK);
   }

   protected static byte[] computeKey(byte[] baseDerivationKey, byte[] keySerialNumber, BitSet keyRegisterBitmask, BitSet dataVariantBitmask) throws Exception {
      BitSet bdk = toBitSet(baseDerivationKey);
      BitSet ksn = toBitSet(keySerialNumber);
      BitSet ipek = getIpek(bdk, ksn, keyRegisterBitmask);

      // convert key for returning
      BitSet key = _getCurrentKey(ipek, ksn, keyRegisterBitmask, dataVariantBitmask);
      byte[] rkey = toByteArray(key);

      // secure memory
      obliviate(ksn);
      obliviate(bdk);
      obliviate(ipek);
      obliviate(key);

      return rkey;
   }

   public static BitSet getIpek(BitSet key, BitSet ksn) throws Exception {
      return getIpek(key, ksn, DEFAULT_KEY_REGISTER_BITMASK);
   }

   protected static BitSet getIpek(BitSet key, BitSet ksn, BitSet keyRegisterBitmask) throws Exception {
      byte[][] ipek = new byte[2][];
      BitSet keyRegister = key.get(0, key.bitSize());
      BitSet data = ksn.get(0, ksn.bitSize());
      data.clear(59, 80);

      ipek[0] = encryptTripleDes(toByteArray(keyRegister), toByteArray(data.get(0, 64)));

      keyRegister.xor(keyRegisterBitmask);
      ipek[1] = encryptTripleDes(toByteArray(keyRegister), toByteArray(data.get(0, 64)));

      byte[] bipek = concat(ipek[0], ipek[1]);
      BitSet bsipek = toBitSet(bipek);

      // secure memory
      obliviate(ipek[0]);
      obliviate(ipek[1]);
      obliviate(bipek);
      obliviate(keyRegister);
      obliviate(data);

      return bsipek;
   }

   private static BitSet _getCurrentKey(BitSet ipek, BitSet ksn, BitSet keyRegisterBitmask, BitSet dataVariantBitmask) throws Exception {
      BitSet key = ipek.get(0, ipek.bitSize());
      BitSet counter = ksn.get(0, ksn.bitSize());
      counter.clear(59, ksn.bitSize());

      for (int i = 59; i < ksn.bitSize(); i++) {
         if (ksn.get(i)) {
            counter.set(i);
            BitSet tmp = _nonReversibleKeyGenerationProcess(key, counter.get(16, 80), keyRegisterBitmask);
            // secure memory
            obliviate(key);
            key = tmp;
         }
      }
      key.xor(dataVariantBitmask); // data encryption variant (e.g. To PIN)

      // secure memory
      obliviate(counter);

      return key;
   }

   private static BitSet _nonReversibleKeyGenerationProcess(BitSet p_key, BitSet data, BitSet keyRegisterBitmask) throws Exception {
      BitSet keyreg = p_key.get(0, p_key.bitSize());
      BitSet reg1 = data.get(0, data.bitSize());
      // step 1: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-2.
      BitSet reg2 = reg1.get(0, 64); // reg2 is being used like a temp here
      reg2.xor(keyreg.get(64, 128));   // and here, too, kind of
      // step 2: Crypto Register-2 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-2
      reg2 = toBitSet(encryptDes(toByteArray(keyreg.get(0, 64)), toByteArray(reg2)));
      // step 3: Crypto Register-2 XORed with the right half of the Key Register goes to Crypto Register-2
      reg2.xor(keyreg.get(64, 128));
      // done messing with reg2

      // step 4: XOR the Key Register with hexadecimal C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000
      keyreg.xor(keyRegisterBitmask);
      // step 5: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
      reg1.xor(keyreg.get(64, 128));
      // step 6: Crypto Register-1 DEA-encrypted using, as the key, the left half of the Key Register goes to Crypto Register-1
      reg1 = toBitSet(encryptDes(toByteArray(keyreg.get(0, 64)), toByteArray(reg1)));
      // step 7: Crypto Register-1 XORed with the right half of the Key Register goes to Crypto Register-1
      reg1.xor(keyreg.get(64, 128));
      // done

      byte[] reg1b = toByteArray(reg1), reg2b = toByteArray(reg2);
      byte[] key = concat(reg1b, reg2b);
      BitSet rkey = toBitSet(key);

      // secure memory
      obliviate(reg1);
      obliviate(reg2);
      obliviate(reg1b);
      obliviate(reg2b);
      obliviate(key);
      obliviate(keyreg);

      return rkey;
   }

   public static byte[] encryptDes(byte[] key, byte[] data, boolean padding) throws Exception {
      IvParameterSpec iv = new IvParameterSpec(new byte[8]);
      SecretKey encryptKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(key));
      Cipher encryptor;
      if (padding) {
         encryptor = Cipher.getInstance("DES/CBC/PKCS5Padding");
      } else {
         encryptor = Cipher.getInstance("DES/CBC/NoPadding");
      }
      encryptor.init(Cipher.ENCRYPT_MODE, encryptKey, iv);
      return encryptor.doFinal(data);
   }

   public static byte[] toDataKey(final byte[] derivedKey) throws Exception {
      if (derivedKey == null || derivedKey.length != 16) {
         throw new IllegalArgumentException("Invalid key provided: " + (derivedKey == null ? "null" : "length " + derivedKey.length));
      }

      byte[] left = Arrays.copyOfRange(derivedKey, 0, 8);
      byte[] right = Arrays.copyOfRange(derivedKey, 8, 16);

      byte[] leftEncrypted = Dukpt.encryptTripleDes(derivedKey, left);
      byte[] rightEncrypted = Dukpt.encryptTripleDes(derivedKey, right);
      byte[] dataKey = Dukpt.concat(leftEncrypted, rightEncrypted);

      Dukpt.obliviate(left);
      Dukpt.obliviate(right);
      Dukpt.obliviate(leftEncrypted);
      Dukpt.obliviate(rightEncrypted);

      return dataKey;
   }

   public static byte[] decryptDes(byte[] key, byte[] data, boolean padding) throws Exception {
      IvParameterSpec iv = new IvParameterSpec(new byte[8]);
      SecretKey decryptKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(key));
      Cipher decryptor;
      if (padding) {
         decryptor = Cipher.getInstance("DES/CBC/PKCS5Padding");
      } else {
         decryptor = Cipher.getInstance("DES/CBC/NoPadding");
      }
      decryptor.init(Cipher.DECRYPT_MODE, decryptKey, iv);
      return decryptor.doFinal(data);
   }

   public static byte[] encryptDes(byte[] key, byte[] data) throws Exception {
      return encryptDes(key, data, false);
   }

   public static byte[] decryptDes(byte[] key, byte[] data) throws Exception {
      return decryptDes(key, data, false);
   }

   public static byte[] encryptTripleDes(byte[] key, byte[] data, boolean padding) throws Exception {
      BitSet bskey = toBitSet(key);
      BitSet k1, k2, k3;
      if (bskey.bitSize() == 64) {
         // single length
         k1 = bskey.get(0, 64);
         k2 = k1;
         k3 = k1;
      } else if (bskey.bitSize() == 128) {
         // double length
         k1 = bskey.get(0, 64);
         k2 = bskey.get(64, 128);
         k3 = k1;
      } else {
         // triple length
         if (bskey.bitSize() != 192) {
            throw new InvalidParameterException("Key is not 8/16/24 bytes long.");
         }
         k1 = bskey.get(0, 64);
         k2 = bskey.get(64, 128);
         k3 = bskey.get(128, 192);
      }
      byte[] kb1 = toByteArray(k1), kb2 = toByteArray(k2), kb3 = toByteArray(k3);
      byte[] key16 = concat(kb1, kb2);
      byte[] key24 = concat(key16, kb3);

      IvParameterSpec iv = new IvParameterSpec(new byte[8]);
      SecretKey encryptKey = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(key24));
      Cipher encryptor;
      if (padding) {
         encryptor = Cipher.getInstance("DESede/CBC/PKCS5Padding");
      } else {
         encryptor = Cipher.getInstance("DESede/CBC/NoPadding");
      }
      encryptor.init(Cipher.ENCRYPT_MODE, encryptKey, iv);
      byte[] bytes = encryptor.doFinal(data);

      // secure memory
      obliviate(k1);
      obliviate(k2);
      obliviate(k3);
      obliviate(kb1);
      obliviate(kb2);
      obliviate(kb3);
      obliviate(key16);
      obliviate(key24);
      obliviate(bskey);

      return bytes;
   }

   public static byte[] decryptTripleDes(byte[] key, byte[] data, boolean padding) throws Exception {
      BitSet bskey = toBitSet(key);
      BitSet k1, k2, k3;
      if (bskey.bitSize() == 64) {
         // single length
         k1 = bskey.get(0, 64);
         k2 = k1;
         k3 = k1;
      } else if (bskey.bitSize() == 128) {
         // double length
         k1 = bskey.get(0, 64);
         k2 = bskey.get(64, 128);
         k3 = k1;
      } else {
         // triple length
         if (bskey.bitSize() != 192) {
            throw new InvalidParameterException("Key is not 8/16/24 bytes long.");
         }
         k1 = bskey.get(0, 64);
         k2 = bskey.get(64, 128);
         k3 = bskey.get(128, 192);
      }
      byte[] kb1 = toByteArray(k1), kb2 = toByteArray(k2), kb3 = toByteArray(k3);
      byte[] key16 = concat(kb1, kb2);
      byte[] key24 = concat(key16, kb3);

      IvParameterSpec iv = new IvParameterSpec(new byte[8]);
      SecretKey encryptKey = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(key24));
      Cipher decryptor;
      if (padding)
         decryptor = Cipher.getInstance("DESede/CBC/PKCS5Padding");
      else
         decryptor = Cipher.getInstance("DESede/CBC/NoPadding");
      decryptor.init(Cipher.DECRYPT_MODE, encryptKey, iv);
      byte[] bytes = decryptor.doFinal(data);

      // secure memory
      obliviate(k1);
      obliviate(k2);
      obliviate(k3);
      obliviate(kb1);
      obliviate(kb2);
      obliviate(kb3);
      obliviate(key16);
      obliviate(key24);
      obliviate(bskey);

      return bytes;
   }

   public static byte[] encryptTripleDes(byte[] key, byte[] data) throws Exception {
      return encryptTripleDes(key, data, false);
   }

   public static byte[] decryptTripleDes(byte[] key, byte[] data) throws Exception {
      return decryptTripleDes(key, data, false);
   }

   public static byte[] encryptAes(byte[] key, byte[] data, boolean padding) throws Exception {
      IvParameterSpec iv = new IvParameterSpec(new byte[16]);
      SecretKeySpec encryptKey = new SecretKeySpec(key, "AES");

      Cipher encryptor;
      if (padding) {
         encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
      } else {
         encryptor = Cipher.getInstance("AES/CBC/NoPadding");
      }
      encryptor.init(Cipher.ENCRYPT_MODE, encryptKey, iv);
      return encryptor.doFinal(data);
   }

   public static byte[] decryptAes(byte[] key, byte[] data, boolean padding) throws Exception {
      IvParameterSpec iv = new IvParameterSpec(new byte[16]);
      SecretKeySpec decryptKey = new SecretKeySpec(key, "AES");

      Cipher decryptor;
      if (padding) {
         decryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
      } else {
         decryptor = Cipher.getInstance("AES/CBC/NoPadding");
      }
      decryptor.init(Cipher.DECRYPT_MODE, decryptKey, iv);
      return decryptor.doFinal(data);
   }

   public static byte[] encryptAes(byte[] key, byte[] data) throws Exception {
      return encryptAes(key, data, false);
   }

   public static byte[] decryptAes(byte[] key, byte[] data) throws Exception {
      return decryptAes(key, data, false);
   }

   public static BitSet toBitSet(byte b) {
      BitSet bs = new BitSet(8);
      for (int i = 0; i < 8; i++) {
         if ((b & (1L << i)) > 0) {
            bs.set(7 - i);
         }
      }
      return bs;
   }

   public static BitSet toBitSet(byte[] b) {
      BitSet bs = new BitSet(8 * b.length);
      for (int i = 0; i < b.length; i++) {
         for (int j = 0; j < 8; j++) {
            if ((b[i] & (1L << j)) > 0) {
               bs.set(8 * i + (7 - j));
            }
         }
      }
      return bs;
   }

   public static byte toByte(BitSet b) {
      byte value = 0;
      for (int i = 0; i < b.bitSize(); i++) {
         if (b.get(i))
            value = (byte) (value | (1L << 7 - i));
      }
      return value;
   }

   public static byte[] toByteArray(BitSet b) {
      int size = (int) Math.ceil(b.bitSize() / 8.0d);
      byte[] value = new byte[size];
      for (int i = 0; i < size; i++) {
         value[i] = toByte(b.get(i * 8, Math.min(b.bitSize(), (i + 1) * 8)));
      }
      return value;
   }

   public static byte[] toByteArray(String s) {
      int len = s.length();
      byte[] data = new byte[len / 2];
      for (int i = 0; i < len; i += 2) {
         data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
      }
      return data;
   }

   public static String toHex(byte[] bytes) {
      BigInteger bi = new BigInteger(1, bytes);
      return String.format("%0" + (bytes.length << 1) + "X", bi);
   }

   public static byte[] concat(byte[] a, byte[] b) {
      byte[] c = new byte[a.length + b.length];
      for (int i = 0; i < a.length; i++) {
         c[i] = a[i];
      }
      for (int i = 0; i < b.length; i++) {
         c[a.length + i] = b[i];
      }
      return c;
   }

   public static void obliviate(BitSet b) {
      obliviate(b, NUM_OVERWRITES);
   }

   public static void obliviate(byte[] b) {
      obliviate(b, NUM_OVERWRITES);
   }

   public static void obliviate(BitSet b, int n) {
      java.security.SecureRandom r = new java.security.SecureRandom();
      for (int i=0; i<NUM_OVERWRITES; i++) {
         for (int j = 0; j<b.bitSize(); j++) {
            b.set(j, r.nextBoolean());
         }
      }
   }

   public static void obliviate(byte[] b, int n) {
      for (int i=0; i<n; i++) {
         b[i] = 0x00;
         b[i] = 0x01;
      }

      java.security.SecureRandom r = new java.security.SecureRandom();
      for (int i=0; i<n; i++) {
         r.nextBytes(b);
      }
   }

}
