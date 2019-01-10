package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * This is an implementation of AES using GCM mode -> Authenticated encryption
 * This type of cipher requires an IV that is preferably 12 bytes long (https://crypto.stackexchange.com/questions/41601/aes-gcm-recommended-iv-size-why-12-bytes/41610)
 *
 * Padding has no effect here, since GCM uses CTR internally (https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode/26787#26787?newreg=3942556a7f664d16a466b114e0fc993e)
 * The random IV must also be sent alongside the cipher text
 *
 * Because this is authenticated encryption, the authentication tags (16 bytes) will be sent alongside the message
 * The decryption automatically checks the tag and throws an error if it fails
 *
 * Authenticated encryption provides protection against padding oracle attacks (https://www.limited-entropy.com/padding-oracle-attacks/)
 */
public class AES_GCM {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        final SecretKey key = KeyGenerator.getInstance("AES").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                SecureRandom secureRandom = new SecureRandom(); // This is used to create a random sequence of bytes that is much safer than just Random
                final byte[] pt = "Hey Bob, It's Alice".getBytes(StandardCharsets.UTF_8);

                System.out.println("PT: "+Agent.hex(pt));

                final byte[] iv = new byte[12];  // Create a random IV, that is used by the parameter spec
                secureRandom.nextBytes(iv); // SecureRandom gives better random values than the Random class, use it to randomize the IV

                final Cipher encryption = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec specs = new GCMParameterSpec(128,iv); // The GCMParameterSpec sets the tag length and the used IV
                encryption.init(Cipher.ENCRYPT_MODE,key,specs);
                final byte[] ct = encryption.doFinal(pt);

                System.out.println("IV: "+Agent.hex(iv));
                System.out.println("CT: "+Agent.hex(ct));

                send("bob", iv);
                send("bob", ct);

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");

                final Cipher encryption = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec specs = new GCMParameterSpec(128,iv);
                encryption.init(Cipher.DECRYPT_MODE,key,specs);
                final byte[] pt = encryption.doFinal(ct);

                System.out.println("PT: "+Agent.hex(pt));

                print(new String(pt, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}