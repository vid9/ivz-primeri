package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

public class Signature_E {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        final String signingAlgorithm = "SHA256withRSA";
        // "SHA256withDSA";
        //"SHA256withECDSA";

        final String keyAlgorithm = "RSA";
        // "RSA";
        // "EC";

        final KeyPair keyPair = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final byte[] document = "We would like to sign this.".getBytes(StandardCharsets.UTF_8);

                final Signature signer = Signature.getInstance(signingAlgorithm);

                signer.initSign(keyPair.getPrivate());

                signer.update(document);

                final byte[] signature = signer.sign();

                System.out.println("Signature: " + Agent.hex(signature));

                send("bob", document);
                send("bob", signature);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] document = receive("alice");
                final byte[] signature = receive("alice");

                final Signature verifier = Signature.getInstance(signingAlgorithm);

                verifier.initVerify(keyPair.getPublic());

                verifier.update(document);

                if (verifier.verify(signature)) {
                    System.out.println("Valid signature.");
                }  else {
                    System.err.println("Invalid signature.");
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}