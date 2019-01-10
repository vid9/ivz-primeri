package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class HandsOnAssignment {
    public static void main(String[] args) throws NoSuchAlgorithmException {

        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final String signingAlgorithm = "SHA256withRSA";
        // "SHA256withDSA";
        //"SHA256withECDSA";

        final String keyAlgorithm = "RSA";
        // "RSA";
        // "EC";

        final KeyPair keyPair = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();

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

                final byte[] signature = receive("bob");
                final byte[] ctBob = receive("bob");
                final byte[] ivBob = receive("bob");

                final Signature verifier = Signature.getInstance(signingAlgorithm);
                verifier.initVerify(keyPair.getPublic());

                verifier.update(ctBob);
                verifier.update(ivBob);

                System.out.println("Signature: "+Agent.hex(signature));

                if (verifier.verify(signature)) {
                    final Cipher two = Cipher.getInstance("AES/CTR/NoPadding");
                    final IvParameterSpec spec = new IvParameterSpec(ivBob);
                    two.init(Cipher.DECRYPT_MODE,key,spec);
                    final byte[] decryptedText = two.doFinal(ctBob);
                    print("Alice recieved: %s", new String(decryptedText, StandardCharsets.UTF_8));
                } else {
                    System.err.println("Invalid signature");
                }
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
                final Cipher bobAnswer = Cipher.getInstance("AES/CTR/NoPadding");
                bobAnswer.init(Cipher.ENCRYPT_MODE,key);
                final byte[] ct = bobAnswer.doFinal("Acknowledged".getBytes(StandardCharsets.UTF_8));
                final byte[] iv2 = bobAnswer.getIV();

                final Signature signer = Signature.getInstance(signingAlgorithm);
                signer.initSign(keyPair.getPrivate());
                signer.update(ct);
                signer.update(iv2);

                final byte[] signature = signer.sign();

                System.out.println("Signature: "+Agent.hex(signature));

                send("alice", signature);
                send("alice", ct);
                send("alice", iv2);

                print("Bob recieved: %s", new String(pt2, StandardCharsets.UTF_8));
                }


        });

        env.connect("alice", "bob");
        env.start();
    }
}
