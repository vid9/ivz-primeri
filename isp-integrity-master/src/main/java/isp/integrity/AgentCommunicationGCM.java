package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

public class AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         *
         *
         */

        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                 * Alice:
                 * - creates an AES/GCM cipher,
                 * - initializes it for encryption and with given key.
                 * - encrypts the messages,
                 * - sends the ciphertext and the IV to Bob.
                 */

                final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                //1. Create cipher
                final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                //2. Initialize it with key
                alice.init(Cipher.ENCRYPT_MODE, key);
                //3. encrypt the message
                final byte[] ct = alice.doFinal(pt);
                //4. Send the message and IV
                final byte[] iv = alice.getIV();
                send("bob", ct);
                send("bob", iv);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                 * Bob:
                 * - receives the ciphertext and the IV
                 * - creates a AES/GCM cipher
                 * - initializes the cipher with decryption mode, the key and the IV
                 * - decrypts the message and prints it.
                 */
                //1. Receive text and IV
                final byte[] ct = receive("alice");
                final byte[] iv = receive("alice");
                //2. Create cipher
                Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                //3. Init cipher with decryption, key and IV
                final GCMParameterSpec specs = new GCMParameterSpec(128,iv);
                bob.init(Cipher.DECRYPT_MODE, key, specs);
                //4. Decrypt and print
                final byte[] pt2 = bob.doFinal(ct);
                System.out.printf("PT: %s%n", Agent.hex(pt2));
                System.out.printf("MSG: %s%n", new String(pt2, StandardCharsets.UTF_8));


            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
