package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Here we hash a message with Sha-256 and check its integrity
 *
 * A message digest provides absolutely no authenticity and is vulnerable to a MITM attack since the attacker can simply
 * compute a new hash for the modified message and send that
 *
 * A use for this type of hashing is a public space where digests are stored so we can compare them
 */
public class Message_Digest {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        final SecretKey key = KeyGenerator.getInstance("AES").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final byte[] messageToBob = "Hey Bob, it's Alice".getBytes(StandardCharsets.UTF_8);

                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");

                final byte[] hashed = digestAlgorithm.digest(messageToBob);

                System.out.println("Message to Bob: " + Agent.hex(messageToBob));
                System.out.println("Hash to Bob: " + Agent.hex(hashed));

                System.out.println("");

                send("bob", messageToBob);
                send("bob", hashed);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] messageFromAlice = receive("alice");
                final byte[] messageFromAliceHash = receive("alice");

                System.out.println("Message from Alice: " + Agent.hex(messageFromAlice));
                System.out.println("Hash from Alice: " + Agent.hex(messageFromAliceHash));

                System.out.println("");

                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");

                final byte[] checkedHash = digestAlgorithm.digest(messageFromAlice);

                if (Arrays.equals(messageFromAliceHash, checkedHash)) {
                    System.out.println("Hashes match");
                } else {
                    System.out.println("Hashes do not match");
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}