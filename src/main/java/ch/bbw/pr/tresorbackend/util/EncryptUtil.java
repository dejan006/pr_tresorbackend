package ch.bbw.pr.tresorbackend.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class EncryptUtil {
    public static SecretKey createSecretKey(String password, String saltB64) throws Exception {
        byte[] salt = Base64.getDecoder().decode(saltB64);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100_000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(keyBytes, "AES"); // return key
    }

    // verschlüsseln
    public static String encrypt(String clearText, SecretKey key) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        // text verschlüsseln
        byte[] encryptedBytes = cipher.doFinal(clearText.getBytes(StandardCharsets.UTF_8));

        byte[] ivPlusCipher = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, ivPlusCipher, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, ivPlusCipher, iv.length, encryptedBytes.length);

        // zusammenfügen + return
        return Base64.getEncoder().encodeToString(ivPlusCipher);
    }

    // Entschlüsseln wieder zu Klartext
    public static String decrypt(String cipherB64, SecretKey key) throws Exception {
        byte[] allBytes = Base64.getDecoder().decode(cipherB64);

        int ivLen = 16;
        byte[] iv = new byte[ivLen];
        byte[] cipherBytes = new byte[allBytes.length - ivLen];

        System.arraycopy(allBytes, 0, iv, 0, ivLen);
        System.arraycopy(allBytes, ivLen, cipherBytes, 0, cipherBytes.length);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        // Entschlüsseln + Return (String)
        byte[] clearBytes = cipher.doFinal(cipherBytes);
        return new String(clearBytes, StandardCharsets.UTF_8);
    }
}
