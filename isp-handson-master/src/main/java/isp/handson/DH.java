package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * ("PK": A = g^a, "SK": a)
 */
public class DH {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                    //***           FIRST PART            ***//
                /*
                 * Alice creates her own DH key pair with 2048-bit key size
                 */

                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH"); //Generate DH keypair

                kpg.initialize(2048);
                final KeyPair keyPair = kpg.generateKeyPair();

                KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH"); // Create and initialize key agreement
                aliceKeyAgree.init(keyPair.getPrivate());

                byte[] publicKey = keyPair.getPublic().getEncoded(); // Encode public key and send it

                print("Alice's contribution to DH: %s", hex(publicKey));

                send("bob", publicKey);

                    //***           FIRST PART            ***//


                    //***           SECOND PART            ***//
                /*
                 * Alice uses Bob's public key for the first (and only) phase
                 * of her version of the DH
                 * protocol.
                 * Before she can do so, she has to instantiate a DH public key
                 * from Bob's encoded key material.
                 */

                byte[] bobPubKeyEnc = receive("bob");

                KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
                PublicKey bobPubKey = aliceKeyFac.generatePublic(x509EncodedKeySpec);

                System.out.println("ALICE: Execute Phase1 ...");

                aliceKeyAgree.doPhase(bobPubKey, true);

                    //***           SECOND PART            ***//

                    //***           THIRD PART            ***//
                /*
                 * At this stage, both Alice and Bob have completed the DH key
                 * agreement protocol.
                 * Both generate the (same) shared secret.
                 */

                final byte[] sharedSecret = aliceKeyAgree.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret,0,16, "AES");

                 /*
                    By default the shared secret will be 32 bytes long, but our cipher requires keys of length 16 bytes
                    IMPORTANT: It is better not to create the key directly from the shared secret, but derive it using a
                    key derivation function
                 */

                final Cipher aliceCipher = Cipher.getInstance("AES/GCM/NoPadding");
                aliceCipher.init(Cipher.ENCRYPT_MODE, aesKey);

                final byte[] ct = aliceCipher.doFinal("Hey Bob, this is Alice".getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aliceCipher.getIV();

                send("bob", iv);
                send("bob", ct);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                    //***           FIRST PART            ***//
                /*
                 * Let's turn over to Bob. Bob has received Alice's public key
                 * in encoded format.
                 * He instantiates a DH public key from the encoded key material.
                 */

                final byte[] alicePublicKeyEnc = receive("alice"); // Receive alice pub key

                KeyFactory bobKeyFactory = KeyFactory.getInstance("DH"); // Initiate DH public key from the encoded key material
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(alicePublicKeyEnc);

                PublicKey alicePublicKey = bobKeyFactory.generatePublic(x509EncodedKeySpec);

                DHParameterSpec dhParameterSpecFromAlice = ((DHPublicKey)alicePublicKey).getParams(); // Get parameters from alice pub key

                KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH"); // Bob creates his own DH pair
                bobKpairGen.initialize(dhParameterSpecFromAlice);
                KeyPair bobKpair = bobKpairGen.generateKeyPair();

                KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH"); // Create and initialize own DH KeyAgreement object
                bobKeyAgree.init(bobKpair.getPrivate());

                byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

                send("alice", bobPubKeyEnc);

                    //***           FIRST PART            ***//

                    //***           SECOND PART            ***//
                /*
                 * Bob uses Alice's public key for the first (and only) phase
                 * of his version of the DH
                 * protocol.
                 */

                System.out.println("BOB: Execute Phase1 ...");

                bobKeyAgree.doPhase(alicePublicKey, true);

                    //***           SECOND PART            ***//

                    //***           THIRD PART            ***//
                /*
                 * At this stage, both Alice and Bob have completed the DH key
                 * agreement protocol.
                 * Both generate the (same) shared secret.
                 */

                final byte[] sharedSecret = bobKeyAgree.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret,0,16, "AES");

                 /*
                    By default the shared secret will be 32 bytes long, but our cipher requires keys of length 16 bytes
                    IMPORTANT: It is better not to create the key directly from the shared secret, but derive it using a
                    key derivation function
                 */

                 final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                 final byte[] iv = receive("alice");
                 final byte[] ct = receive("alice");

                 aes.init(Cipher.DECRYPT_MODE,aesKey, new GCMParameterSpec(128,iv));

                 final byte[] pt = aes.doFinal(ct);

                 print("Bob recieved: %s", new String(pt, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }


}