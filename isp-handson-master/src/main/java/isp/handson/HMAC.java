package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Here we see how to provide both integrity and authenticity
 * An HMAC is a hashing function that takes a secret key as an input
 *
 * A MITM attack is useless (if the attacker does not know the key of course) since the attacker cannot compute a valid HMAC for a
 * message he modified
 */
public class HMAC {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        final SecretKey key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final byte[] message = "Hey Bob, it's Alice".getBytes(StandardCharsets.UTF_8);

                final Mac aliceMac = Mac.getInstance("HmacSHA256");

                aliceMac.init(key);

                final byte[] aliceTag = aliceMac.doFinal(message);

                System.out.println("Alice HMAC: " + Agent.hex(aliceTag));

                send("bob", message);
                send("bob", aliceTag);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] messageFromAlice = receive("alice");
                final byte[] aliceHMAC = receive("alice");

                final Mac bobMac = Mac.getInstance("HmacSHA256");

                bobMac.init(key);

                final byte[] computedHMAC = bobMac.doFinal(messageFromAlice);

                System.out.println("Computed HMAC: " + Agent.hex(computedHMAC));

                if (secureVerify(aliceHMAC, computedHMAC, key)) {
                    System.out.println("HMACs match");
                } else {
                    System.out.println("HMACs do not match");
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    /**
     *  The comparison is done byte by byte
     *  The comparator returns false immediately after the first inequality of bytes is found
     *  This is vulnerable to a side-channel attack
     *
     * @param tag1
     * @param tag2
     * @return
     */
    public static boolean insecureVerify(byte[] tag1, byte[] tag2) {
        return Arrays.equals(tag1, tag2);
    }

    /**
     * The idea is to compare all bytes
     * However a "smart" compiler may try to optimize this code and end the loop prematurely, which completely destroys the process
     *
     * @param tag1
     * @param tag2
     * @return
     */
    public static boolean possiblySecureVerify(byte[] tag1, byte[] tag2) {
        if (tag1 == tag2)
            return true;
        if (tag1 == null || tag2 == null)
            return false;

        int length = tag1.length;

        if (tag2.length != length) return false;

        byte result = 0;

        for (int i = 0; i < length; i++) {
            result |= tag1[i] ^ tag2[i];
        }

        return result == 0;
    }

    /**
     * The idea is to hide which bytes are actually being compared by MAC-ing the tags once more and then comparing those tags
     *
     * @param tag1
     * @param tag2
     * @param key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static boolean secureVerify(byte[] tag1, byte[] tag2, Key key) throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance("HmacSHA256");

        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }
}