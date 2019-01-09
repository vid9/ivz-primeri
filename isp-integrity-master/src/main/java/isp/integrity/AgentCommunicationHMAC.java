package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/*
 * Message Authenticity and Integrity are provided using Hash algorithm and Shared Secret Key.
 * http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Mac
 */
public class AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * STEP 1: Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key secretKey = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                 * STEP 3.
                 * Alice
                 * - creates a message;
                 * - computes the tag using the HMAC-SHA-256 algorithm and the shared key;
                 * - sends a message that is comprised of:
                 *   - message,
                 *   - tag.
                 */
                //1. Create a message
                final String text = "I hope you get this message intact. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                //2. Compute the tag
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(secretKey);
                byte[] tag1 = mac.doFinal(pt);
                //3. Send message and tag
                send("bob", pt);
                send("bob", tag1);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                 * Bob:
                 * - receives the message that is comprised of:
                 *   - message, and
                 *   - tag;
                 * - uses shared secret session key to verify the message
                 */
                //1. Receive message and tag
                final byte[] pt = receive("alice");
                final byte[] tag1 = receive("alice");
                //2. Use shared secret session key to verify the message
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(secretKey);
                final byte[] tag2 = mac.doFinal(pt);
                final byte[] tag11 = mac.doFinal(tag1);
                final byte[] tag22 = mac.doFinal(tag2);

                System.out.println(Arrays.equals(tag11,tag22));

            }
        });



        env.connect("alice", "bob");
        env.start();
    }
}
