package isp.handson;

import fri.isp.Agent;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * This is an example of password-based encryption
 *
 * (https://www.javamex.com/tutorials/cryptography/pbe_salt.shtml)
 */
public class Key_Derivation {
    public static void createKeyFromPassword(byte[] sharedSecret) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Password from which the key will be derived
        final String password = "password";

        // Salt is supposed to be random
        final byte[] salt = "89fjh3409fdj390fk".getBytes(StandardCharsets.UTF_8);

        final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        // provide the password, salt, number of iterations and the number of required bits
        final KeySpec specs = new PBEKeySpec(password.toCharArray(), salt, 1000000, 128);

        final SecretKey key = secretKeyFactory.generateSecret(specs);

        System.out.printf("key = %s%n", Agent.hex(key.getEncoded()));
        System.out.printf("len(key) = %d bytes", key.getEncoded().length);
    }

    /**
     * This function hashes the shared secret using SHA-256
     * (https://stackoverflow.com/questions/35265635/key-derivation-function-for-shared-secret-generated-by-diffie-hellman-key-exchan)
     *
     * @param sharedSecret
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] deriveKey(byte[] sharedSecret) throws NoSuchAlgorithmException {
        final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");

        final byte[] hashedKey = digestAlgorithm.digest(sharedSecret);

        return Arrays.copyOfRange(hashedKey, 0, 16);
    }
}