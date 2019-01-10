package isp.handson;

import com.sun.deploy.util.ArrayUtil;
import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * We are performing a length-extension attack, which takes advantage of the vulnerability in the Merkle–Damgård construction
 * of hash algorithms like MD5, SHA-1 and SHA-2
 *
 * The key to understanding hash extension attacks is to understand that the hash output isn't just the output of the machine
 * generating the hash, it's also the state of the machine up till that point. In other words, just the hash output alone
 * contains enough information for you to keep going and append more content to the hashed input (https://crypto.stackexchange.com/questions/3978/understanding-the-length-extension-attack)
 *
 * Alice is using a MAC that looks like H(message || secret) and if the message and only the length of the secret is known
 * the attacker may include additional information at the end of the message and produce a valid hash without knowing the secret
 *
 * We are a Man-in-the-middle who knows the length of the plaintext and we can assume the length of the secret, therefore we
 * can perform this attack
 *
 * To sign a new message, the attacker needs to know the secret key, however we can feed the hash we received for the original
 * message into the state of the hashing algorithm used (SHA-1 in this case) and continue from there -> To manually set the
 * internal state of the SHA-1 algorithm, use the {@link ModifiedSHA1} class
 *
 * We also need to include the necessary padding bits in our message, because most hash functions only work on messages that
 * are a multiple of some size -> SHA-1 for example uses 64 byte blocks
 * The computed hash has already padded the last block if necessary, so the main thing is just getting the bytes to line up correctly
 * Padding construction:
 *     - the padding starts with \x80
 *     - the needed padding space is filled with \x00s
 *     - the last 8 bytes represent the data length in bits (without padding)
 *
 * We can also try sending replay attacks with this construction, but that's not the point here
 *
 * Taken from https://en.wikipedia.org/wiki/Length_extension_attack
 */
public class Homework_2 {
    public static void main(String[] args) throws Exception {
        // Alice and the bank have a shared secret, and its length is known to the attacker.
        final byte[] sharedSecret = new byte[16];

        // For debugging purposes, I recommend using a static secret (like all zeros).
        // Your solution, however, must work with an arbitrary secret.
        // So for debugging, comment out the following two lines.
        final SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(sharedSecret);

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "Wire 10 EUR to MITM.";

                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                final MessageDigest d = MessageDigest.getInstance("SHA-1");

                d.update(sharedSecret);

                d.update(pt);

                final byte[] tag = d.digest();

                print("data  = %s", message);
                print("pt    = %s", hex(pt));
                print("tag   = %s", hex(tag));

                send("bank", pt);
                send("bank", tag);
            }
        });

        env.add(new Agent("mitm") {
            @Override
            public void task() throws Exception {
                final byte[] message = receive("alice");
                final byte[] tag = receive("alice");

                // Data to be added
                byte[] addition = " And then, in a separate transaction, wire 1,000,000 EUR more."
                        .getBytes(StandardCharsets.UTF_8);

                final int hashedMessageLength = message.length + sharedSecret.length;

                final double blockSize = 64;

                ModifiedSHA1 modifiedSHA1 = new ModifiedSHA1();

                // Get the number of hashed 64 byte blocks
                long numberOfHashedBlocks = (long) Math.ceil(hashedMessageLength / blockSize);

                /*
                    Set the SHA-1 state to the computed hash, this can be done because the outputted hash from Alice is
                    actually the state of the SHA-1 algorithm at the time of stopping
                 */
                modifiedSHA1.setState(tag, numberOfHashedBlocks);

                // Update adds the byte array to the state
                modifiedSHA1.update(addition);

                // Here we actually compute the new malicious tag
                final byte[] modifiedTag = modifiedSHA1.digest();

                int paddingSize = (int) ((numberOfHashedBlocks * 64) - hashedMessageLength);

                byte[] padding = constructPadding(paddingSize, hashedMessageLength);

                // Prepend the padding to the malicious message
                addition = joinByteArrays(padding, addition);

                // The modified message is now ready alongside the newly computed tag
                final byte[] modifiedMessage = joinByteArrays(message, addition);

                //send("bank", pt);
                //send("bank", tag);

                send("bank", modifiedMessage);
                send("bank", modifiedTag);
            }
        });

        env.add(new Agent("bank") {
            @Override
            public void task() throws Exception {
                final byte[] pt = receive("alice");
                final byte[] tag = receive("alice");

                // recompute the tag
                final MessageDigest d = MessageDigest.getInstance("SHA-1");

                d.update(sharedSecret);

                d.update(pt);

                final byte[] tagComputed = d.digest();

                print("data = %s", new String(pt, StandardCharsets.UTF_8));
                print("pt   = %s", hex(pt));

                if (Arrays.equals(tag, tagComputed))
                    print("MAC verification succeeds: %s == %s", hex(tag), hex(tagComputed));
                else
                    print("MAC verification fails: %s != %s", hex(tag), hex(tagComputed));
            }
        });

        env.mitm("alice", "bank", "mitm");
        env.start();
    }

    private static byte[] joinByteArrays(byte[] arr1, byte[] arr2) {
        byte[] concatenatedArray = new byte[arr1.length + arr2.length];

        /*
            Copy the source array from the starting index to the destination array at source index with some
            specified length
         */

        System.arraycopy(arr1, 0, concatenatedArray, 0, arr1.length);
        System.arraycopy(arr2, 0, concatenatedArray, arr1.length, arr2.length);

        return concatenatedArray;
    }

    private static byte[] constructPadding(int paddingSize, int hashedMessageLength) {
        byte[] padding = new byte[paddingSize];

        padding[0] = (byte) 0x80;

        for (int i = 1; i < paddingSize - 4; i++) {
            padding[i] = (byte) 0x00;
        }

        // Convert the message length to bits
        hashedMessageLength *= 8;

        /*
            We need to take care of which endian to choose -> here we need the Big Endian, where the most significant byte
            is in the lowest address (https://chortle.ccsu.edu/AssemblyTutorial/Chapter-15/ass15_3.html)
            To convert an int to a byte we need a byte array of 4 (since an int is 4 bytes or 32 bits) .The operation is
            very simple, just bit shift the selected octet to the first 8 bits and cast to byte. When casting from int to
            byte java will simply cut off all the octets after the first 8 bits and we are left with our byte (Downcasting).
         */
        padding[paddingSize - 4] = (byte) (hashedMessageLength >> 24);
        padding[paddingSize - 3] = (byte) (hashedMessageLength >> 16);
        padding[paddingSize - 2] = (byte) (hashedMessageLength >> 8);
        padding[paddingSize - 1] = (byte) hashedMessageLength;

        return padding;
    }
}