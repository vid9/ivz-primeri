package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.*;

/*
 * An agent communication example. The authenticity and integrity of messages
 * are provided with the use of digital signatures.
 * <p/>
 * Additionally, since the signing key (private key) is owned only by the signer,
 * we can be certain that valid signature can only be provided by that party. This
 * provides an additional property called non-repudiation.
 */
public class AgentCommunicationSignature {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        // Alice creates public and private key.
        // Bob receives her public key.
        final KeyPair keyPairAlice = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final PublicKey pkAlice = keyPairAlice.getPublic();
        final PrivateKey skAlice = keyPairAlice.getPrivate();

        /*
         * Alice:
         * - uses private key to sign message.
         * - sends a 2-part message:
         *   * message
         *   * signature
         */
        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                 * Alice writes a message and sends to Bob.
                 */
                final String text = "I love you Bob. Kisses, Alice.";
                send("bob", text.getBytes(StandardCharsets.UTF_8));

                // Todo: Sign the message using algorithm "SHA256withRSA"
            }
        });

        /*
         * Bob :
         * - receives a 2-part message:
         *   * message
         *   * Signature
         * - uses Alice's public key to verify message authenticity and integrity.
         */
        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Todo: receive the message and its signature
                // Todo: verify the signature using Alice's public key
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}