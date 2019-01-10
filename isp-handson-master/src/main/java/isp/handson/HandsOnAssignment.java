package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandsOnAssignment {
    public static void main(String[] args) throws NoSuchAlgorithmException {

        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final byte[] dataForBob = "The package is in room 102".getBytes(StandardCharsets.UTF_8);

                final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                alice.init(Cipher.ENCRYPT_MODE,key);
                final byte[] ct = alice.doFinal(dataForBob);
                final byte[] iv = alice.getIV();
                send("bob", ct);
                send("bob", iv);

                final byte[] ctBob = receive("bob");
                final byte[] ivBob = receive("bob");
                

                final Cipher two = Cipher.getInstance("AES/CTR/NoPadding");
                final IvParameterSpec spec = new IvParameterSpec(ivBob);
                two.init(Cipher.DECRYPT_MODE,key,spec);
                final byte[] decryptedText = two.doFinal(ctBob);


            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] dataFromAlice = receive("alice");
                final byte[] iv = receive("alice");
                Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128,iv);
                bob.init(Cipher.DECRYPT_MODE,key,specs);

                final byte[] pt2 = bob.doFinal(dataFromAlice);
                if (pt2.equals("The package is in room 102".getBytes(StandardCharsets.UTF_8))) {
                    final MessageDigest digest = MessageDigest.getInstance("SHA256withRSA");
                    final byte[] hashed = digest.digest("Acknowledged".getBytes(StandardCharsets.UTF_8));

                    final Cipher bobAnswer = Cipher.getInstance("AES/CTR/NoPadding");
                    bobAnswer.init(Cipher.ENCRYPT_MODE,key);
                    final byte[] ct = bobAnswer.doFinal(hashed);
                    final byte[] iv2 = bobAnswer.getIV();


                    send("alice", ct);
                    send("alice", iv2);
                }
                print("Got '%s'", new String(dataFromAlice, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
