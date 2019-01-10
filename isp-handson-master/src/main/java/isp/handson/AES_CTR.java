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
 * This turns a block cipher into a stream cipher basically, therefore no padding is required
 * Output cipher text is the same length as the plain text
 * Always use the same key and IV pair ONCE! If the pair is used multiple times, we are vulnerable to a two-time pad attack
 *
 * If we know the plain text we can easily and predictably change the cipher text by flipping bits
 * (as seen in the man-in-the-middle homework exercise)
 *
 * In CBC (and CTR mode), you have to also
 * send the IV. The IV can be accessed via the
 * encryption.getIV() call
 */
public class AES_CTR {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        final SecretKey key = KeyGenerator.getInstance("AES").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final byte[] pt = "Hey Bob, it's Alice".getBytes(StandardCharsets.UTF_8);

                System.out.println("PT: " + Agent.hex(pt));

                Cipher encryption = Cipher.getInstance("AES/CTR/NoPadding");
                encryption.init(Cipher.ENCRYPT_MODE,key);
                final byte[] iv = encryption.getIV();
                final byte[] ct = encryption.doFinal(pt);

                //ct = stimulateAttack(ct);

                send("bob",iv);
                send("bob", ct);

                System.out.println("CT: " + Agent.hex(ct));
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");

                Cipher encryption = Cipher.getInstance("AES/CTR/NoPadding");
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

    /**
     * This function shows the vulnerability of CTR mode which has no authentication
     * If an attacker knows the part of the original plaintext message, they can very easily and predictably
     * change the plaintext even without knowing the key -> this is because it is basically a stream cipher with
     * a known length
     *
     * @param ciphertext
     * @return
     */
    public static byte[] simulateAttack(byte[] ciphertext) {
        byte[] plaintext = "Hey Bob, it's Alice".getBytes(StandardCharsets.UTF_8);

        ciphertext[0] = (byte) (ciphertext[0] ^ plaintext[0] ^ (byte) 'D');
        ciphertext[1] = (byte) (ciphertext[1] ^ plaintext[1] ^ (byte) 'i');
        ciphertext[2] = (byte) (ciphertext[2] ^ plaintext[2] ^ (byte) 'e');

        return ciphertext;
    }
}