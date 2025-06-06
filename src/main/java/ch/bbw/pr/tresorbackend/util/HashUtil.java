package ch.bbw.pr.tresorbackend.util;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class HashUtil {

    private static final int ITERATIONS = 100_000;
    private static final int KEY_LENGTH = 256;
    private static final String ALGO = "PBKDF2WithHmacSHA256";
    private static final SecureRandom RNG = new SecureRandom();

    // salt generieren
    public static String generateSalt() {
        byte[] salt = new byte[16];
        RNG.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // passwort Hashing
    public static String hashPassword(String password, String saltB64, String pepper) throws Exception {
        // pepper + passwort
        char[] chars = (password + pepper).toCharArray();
        byte[] salt = Base64.getDecoder().decode(saltB64);

        PBEKeySpec spec = new PBEKeySpec(chars, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGO);
        byte[] hash = skf.generateSecret(spec).getEncoded();

        return Base64.getEncoder().encodeToString(hash);
    }

    // Passwort Verifizierung
    public static boolean verifyPassword(String password, String saltB64, String pepper, String expectedHash) throws Exception {
        String hash = hashPassword(password, saltB64, pepper);
        return hash.equals(expectedHash);
    }
}
