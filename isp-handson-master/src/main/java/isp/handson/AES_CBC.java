package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

/**
 * AES in CBC mode requires a key and initialization vector IV (16 bytes)
 * Every block is dependent on the block before it, as it is xor-ed with it together with the key (16 bytes)
 * The first block is xor-ed with the IV and the key
 *
 * Padding has no security implications so just use PKCS5Padding
 * If the input is not a multiple of 16 bytes padding is required!
 *
 * In CBC (and CTR mode), you have to also
 * send the IV. The IV can be accessed via the
 * encryption.getIV() call
 *
 * The attack used in CTR mode does not work here, even if the attacker knows the part of the plaintext,
 * because every change in a block will affect every block after it -> the decrypted ciphertext will result in gibberish
 * The recipient however has no idea that the ciphertext was tampered with, since no authentication was provided
 * CBC mode is susceptible to an attack known as padding oracle attacks (https://www.limited-entropy.com/padding-oracle-attacks/)
 *
 */
public class AES_CBC {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        final SecretKey key = KeyGenerator.getInstance("AES").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final byte[] pt = "Hey Bob, it's Alice".getBytes(StandardCharsets.UTF_8);

                System.out.println("PT: " + Agent.hex(pt));

                final Cipher encryption = Cipher.getInstance("AES/CBC/PKCS5Padding"); //Declare cipher
                encryption.init(Cipher.ENCRYPT_MODE,key); // Initialize cipher encrypt mode with key
                final byte[] iv = encryption.getIV(); // Get IV
                byte[] ct = encryption.doFinal(pt);

                System.out.println("CT: " + Agent.hex(ct));

                //ct = simulateAttack(ct); //Stimulate an attack on the ciphertext

                // The IV may be sent unencrypted and over an insecure channel
                send("bob", iv);
                send("bob", ct);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");

                final Cipher encryption = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec specs = new IvParameterSpec(iv);
                encryption.init(Cipher.DECRYPT_MODE,key,specs);
                final byte[] pt = encryption.doFinal(ct);


                System.out.println("PT: " + Agent.hex(pt));

                print(new String(pt, StandardCharsets.UTF_8));

            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    public static byte[] simulateAttack(byte[] ciphertext) {
        byte[] plaintext = "Hey Bob, it's Alice".getBytes(StandardCharsets.UTF_8);

        ciphertext[0] = (byte) (ciphertext[0] ^ plaintext[0] ^ (byte) 'D');
        ciphertext[1] = (byte) (ciphertext[1] ^ plaintext[1] ^ (byte) 'i');
        ciphertext[2] = (byte) (ciphertext[2] ^ plaintext[2] ^ (byte) 'e');

        return ciphertext;
    }
}