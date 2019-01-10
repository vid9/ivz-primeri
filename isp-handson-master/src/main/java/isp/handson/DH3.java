package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * This example demonstrates a multi-party communication, that is a communication between
 * more than two agents.
 */
public class DH3 {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Environment env = new Environment();

        //This DH parameters can also be constructed by creating a
        //DHParameterSpec object using agreed-upon values
        final KeyPair sharedKey = KeyPairGenerator.getInstance("DH").generateKeyPair();
        final DHParameterSpec dhParamShared = ((DHPublicKey)sharedKey.getPublic()).getParams();

        env.add(new Agent("alice") {
            public void task() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException {

                // Alice creates her own DH key pair with 2048-bit key size
                System.out.println("ALICE: Generate DH keypair ...");
                KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
                aliceKpairGen.initialize(dhParamShared);
                KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

                // Alice initialize
                System.out.println("ALICE: Initialize ...");
                KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
                aliceKeyAgree.init(aliceKpair.getPrivate());

                byte[] publicKey = aliceKpair.getPublic().getEncoded();
                send("bob", publicKey);

                // Alice uses Charlie's public key
                byte[] charlieKpairEnc = receive("charlie");

                KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(charlieKpairEnc);
                PublicKey charliePubKey = aliceKeyFac.generatePublic(x509EncodedKeySpec);

                Key kac = aliceKeyAgree.doPhase(charliePubKey, false);

                byte[] ac = kac.getEncoded();
                send("bob", ac);


                byte[] cbe = receive("charlie");
                x509EncodedKeySpec = new X509EncodedKeySpec(cbe);
                charliePubKey = aliceKeyFac.generatePublic(x509EncodedKeySpec);

                // Alice uses Charlie's result from above
                aliceKeyAgree.doPhase(charliePubKey, true);


                byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
                System.out.println("Alice secret: " + Agent.hex(aliceSharedSecret));
/*
                byte[] bobSharedSecret = bobKeyAgree.generateSecret();
                System.out.println("Bob secret: " + Agent.hex(bobSharedSecret));

                if (!Arrays.equals(aliceSharedSecret, bobSharedSecret))
                    throw new Exception("Alice and Bob differ");
                System.out.println("Alice and Bob are the same");*/


            }
        });
        env.add(new Agent("bob") {
            public void task() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {

                // Bob creates his own DH key pair using the same params
                System.out.println("BOB: Generate DH keypair ...");
                KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
                bobKpairGen.initialize(dhParamShared);
                KeyPair bobKpair = bobKpairGen.generateKeyPair();

                // Bob initialize
                System.out.println("BOB: Initialize ...");
                KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
                bobKeyAgree.init(bobKpair.getPrivate());

                byte[] publicKey = bobKpair.getPublic().getEncoded();
                send("charlie", publicKey);

                // Bob uses Alice's public key
                byte[] aliceKpairEnc = receive("alice");

                KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(aliceKpairEnc);
                PublicKey alicePubKey = bobKeyFac.generatePublic(x509EncodedKeySpec);

                // Bob uses Alice's public key
                Key kba = bobKeyAgree.doPhase(alicePubKey, false);

                byte[] ba = kba.getEncoded();
                send("charlie", ba);

                byte[] ace = receive("alice");
                x509EncodedKeySpec = new X509EncodedKeySpec(ace);
                alicePubKey = bobKeyFac.generatePublic(x509EncodedKeySpec);


                // Bob uses Alice's result from above
                bobKeyAgree.doPhase(alicePubKey, true);

                byte[] bobSharedSecret = bobKeyAgree.generateSecret();
                System.out.println("Bob secret: " + Agent.hex(bobSharedSecret));

                /*
                byte[] charlieSharedSecret = bobKeyAgree.generateSecret();
                System.out.println("Charlie secret: " + Agent.hex(charlieSharedSecret));

                if (!java.util.Arrays.equals(bobSharedSecret, charlieSharedSecret))
                    throw new Exception("Bob and Carol differ");
                System.out.println("Bob and Carol are the same");*/

            }
        });
        env.add(new Agent("charlie") {
            public void task() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException {

                System.out.println("CAROL: Generate DH keypair ...");
                KeyPairGenerator carolKpairGen = KeyPairGenerator.getInstance("DH");
                carolKpairGen.initialize(dhParamShared);
                KeyPair charlieKpair = carolKpairGen.generateKeyPair();

                System.out.println("CAROL: Initialize ...");
                KeyAgreement charlieKeyAgree = KeyAgreement.getInstance("DH");
                charlieKeyAgree.init(charlieKpair.getPrivate());

                byte[] publicKey = charlieKpair.getPublic().getEncoded();
                send("alice", publicKey);


                byte[] bobKpairEnc = receive("bob");

                KeyFactory charlieKeyFac = KeyFactory.getInstance("DH");
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(bobKpairEnc);
                PublicKey bobPubKey = charlieKeyFac.generatePublic(x509EncodedKeySpec);


                // Charlie uses Bob's public key
                Key kcb = charlieKeyAgree.doPhase(bobPubKey, false);

                byte[] cb = kcb.getEncoded();
                send("alice", cb);


                byte[] ace = receive("bob");
                x509EncodedKeySpec = new X509EncodedKeySpec(ace);
                bobPubKey = charlieKeyFac.generatePublic(x509EncodedKeySpec);

                // Charlie uses Bob's result from above
                charlieKeyAgree.doPhase(bobPubKey, true);

                byte[] carolSharedSecret = charlieKeyAgree.generateSecret();
                System.out.println("Carol secret: " + Agent.hex(carolSharedSecret));

            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "charlie");
        env.connect("charlie", "bob");
        env.start();
    }
}
