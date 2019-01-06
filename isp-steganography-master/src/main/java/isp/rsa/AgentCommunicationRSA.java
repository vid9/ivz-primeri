package isp.rsa;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final String algorithm = "RSA/ECB/NoPadding";//OAEPadding

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                // STEP 1: Create an RSA cipher and encrypt a message using Bob's PK
                 final Cipher rsaEnc = Cipher.getInstance(algorithm);
                 rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                 final byte[] ct = rsaEnc.doFinal();

                 // STEP 2: Send the CT to Bob
                 send("bob", ct);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // STEP 1: Take the incoming message from the queue
                final byte[] ct = receive("alice");

                // STEP 2: Create an RSA cipher and decrypt incoming CT using Bob's SK
                final Cipher rsaDec = Cipher.getInstance(algorithm);
                rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                final byte[] decryptedText = rsaDec.doFinal(ct);

                // STEP 3: Print the message
                System.out.println("PT: " + Agent.hex(decryptedText));

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
