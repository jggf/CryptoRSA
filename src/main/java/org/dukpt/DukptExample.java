package org.dukpt;

import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.params.DESParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DukptExample {

   public static void main(String[] args) throws Exception {
      String ksnStr = "FFFF9876543210E00008";
      String keyStr = "0123456789ABCDEFFEDCBA9876543210";
      String encryptedDataStr = "5E5CAB3FDD38C5FE";

      byte[] ksn = Hex.decode(ksnStr);
      byte[] keyBytes = Hex.decode(keyStr);
      byte[] encryptedData = Hex.decode(encryptedDataStr);

      // Derive the key using DUKPT
      SecretKey derivedKey = null;//deriveDukptKey(keyBytes, ksn);

      // Decrypt the data using the derived key and the counter mode
      byte[] decryptedData = decryptData(encryptedData, derivedKey);

      System.out.println("Decrypted data: " + Hex.toHexString(decryptedData));
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
}
