package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * This example uses DES in CBC mode
 * This encryption scheme is very broken, since the key can be brute forced quite easily
 *
 * DES CBC scheme requires a key (8 bytes) and an IV (8 bytes)
 *
 *
 * The same principle is used in 3DES, which is still considered secure
 * 3DES CBC scheme requires a key (16 or 24 bytes) and an IV (16 or 24 bytes)
 *
 * This example is just to showcase DES, all other examples of block cipher modes are covered with the AES examples
 */
public class DES_CBC {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        final SecretKey key = KeyGenerator.getInstance("DES").generateKey();

        SecureRandom secureRandom = new SecureRandom();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final byte[] plaintext = "Hey Bob, it's Alice".getBytes(StandardCharsets.UTF_8);

                System.out.println("PT: " + Agent.hex(plaintext));

                byte[] iv = new byte[8];
                secureRandom.nextBytes(iv);

                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

                Cipher encryption = Cipher.getInstance("DES/CBC/PKCS5Padding");

                /*
                    IVs may be created manually and added in the encryption initialization or fetched after the init method
                    with encryption.getIV()
                 */
                encryption.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);

                // encryption.init(Cipher.ENCRYPT_MODE, key); // Get the IV with encryption.getIV()

                byte[] ciphertext = encryption.doFinal(plaintext);

                System.out.println("CT: " + Agent.hex(ciphertext));

                send("bob", iv);

                // send("bob", encryption.getIV());

                send("bob", ciphertext);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] iv = receive("alice");
                final byte[] ciphertext = receive("alice");

                Cipher encryption = Cipher.getInstance("DES/CBC/PKCS5Padding");

                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

                encryption.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);

                byte[] plaintext = encryption.doFinal(ciphertext);

                System.out.println("PT: " + Agent.hex(plaintext));

                print(new String(plaintext, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}