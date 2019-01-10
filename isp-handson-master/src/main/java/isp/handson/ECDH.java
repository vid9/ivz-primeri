package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class ECDH {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");

                kpg.initialize(256);

                final KeyPair keyPair = kpg.generateKeyPair();

                byte[] publicKey = keyPair.getPublic().getEncoded();

                print("Alice's contribution to DH: %s", hex(publicKey));

                send("bob", publicKey);

                /*
                    Receive public key from Bob
                    The key exchange is now finished, both entities have all the values they require
                 */

                byte[] receivedPublicKey = receive("bob");

                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receivedPublicKey);

                final ECPublicKey bobPublicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");

                dh.init(keyPair.getPrivate());

                dh.doPhase(bobPublicKey, true);

                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));

                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");

                aes.init(Cipher.ENCRYPT_MODE, aesKey);

                final byte[] ct = aes.doFinal("Hey Bob!".getBytes(StandardCharsets.UTF_8));

                final byte[] iv = aes.getIV();

                send("bob", iv);
                send("bob", ct);

                print("I'm, done!");
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                byte[] receivedPublicKey = receive("alice");

                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receivedPublicKey);

                final ECPublicKey alicePublicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                final ECParameterSpec dhParamSpec = alicePublicKey.getParams();

                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(dhParamSpec);

                final KeyPair keyPair = kpg.generateKeyPair();

                byte[] publicKey = keyPair.getPublic().getEncoded();

                print("Bob's contribution to DH: %s", hex(publicKey));

                send("alice", publicKey);


                /*
                    The key exchange is now finished, both entities have all the values they require
                 */

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");

                dh.init(keyPair.getPrivate());

                dh.doPhase(alicePublicKey, true);

                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));

                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");

                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");

                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));

                final byte[] pt = aes.doFinal(ct);

                print("I got: %s", new String(pt, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}