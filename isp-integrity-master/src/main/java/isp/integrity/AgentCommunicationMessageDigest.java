package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * An MITM example showing how merely using a collision-resistant hash
 * function is insufficient to protect against tampering
 */
public class AgentCommunicationMessageDigest {

    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                 * Alice:
                 * - sends a message that consists of:
                 *   - a message
                 *   - and a message Digest
                 */
                final byte[] message = "I hope you get this message intact. Kisses, Alice.".getBytes(StandardCharsets.UTF_8);
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");

                final byte[] hashed = digestAlgorithm.digest(message);

                send("bob", hashed);

                // String hashAsHex = Agent.hex(hashed);
                //System.out.println(hashAsHex);
                // TODO: Create the digest and send the (message, digest) pair
            }
        });

        env.add(new Agent("mallory") {
            @Override
            public void task() throws Exception {
                // Intercept the message from Alice
                final byte[] message = receive("alice");
                final byte[] tag = receive("alice");

                // TODO: Modify the message

                System.out.println("hello");
                // Forward the modified message
                send("bob", message);
                send("bob", tag);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                 * Bob
                 * - receives the message that is comprised of:
                 *   - message
                 *   - message digest
                 * - checks if received and calculated message digest checksum match.
                 */
                final byte[] message = receive("alice");
                final byte[] tag1 = receive("alice");

                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] tag2 = digestAlgorithm.digest(message);

                final byte[] tag11 = digestAlgorithm.digest(tag1);
                final byte[] tag22 = digestAlgorithm.digest(tag2);

                System.out.println(Arrays.equals(tag11,tag22));
                final String tag111 = Agent.hex(tag11);
                final String tag222 = Agent.hex(tag22);
                System.out.println(tag111);
                System.out.println(tag222);


                // TODO: Check if the received (message, digest) pair is valid
            }
        });

        env.mitm("alice", "bob", "mallory");
        env.start();
    }
}
