package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

/**
 * This example uses the RSA/ECB/NoPadding transformation
 *
 * RSA is an asymmetric cipher, which means it uses a key pair (a public key and a private key)
 * All data encrypted with one of the keys may be decrypted with the other one
 *
 * RSA is very computationally expensive though, so it is usually used alongside symmetric ciphers to securely send the
 * shared secret over an insecure channel
 *
 * The RSA encryption process can only handle about 128 bytes at a time (https://stackoverflow.com/questions/13500368/encrypt-and-decrypt-large-string-in-java-using-rsa)
 *
 * Padding should also be used for security reasons (https://stackoverflow.com/questions/19623367/rsa-encryption-decryption-using-java)
 * If no padding is used, the plain text we decrypt will not be the same length as the original plain text (will have zeroes added in front),
 * but the size of the cipher text
 *
 * Example for NoPadding:
 *      PT: 48657920426F622C206974277320416C696365
 *      CT: 6F1BD449D7520F5438F32F1C1F2DD3F8207B1B5414F745F7C1CA4071964647E2550157494428DB2D9B0D0CC7A1B92CAE3CA59C8990347722C8BEDAFD24D971232A3527BF960322DC171C3600027659E94233B031B0421C0F0DAFE37ED23C3D401203C8677A81C15B20C3FB4DB9644E36ED1870693872C35328B7B7E32AC48318
 *      PT: 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000048657920426F622C206974277320416C696365
 *
 * Example for OAEPWithSHA1AndMGF1Padding:
 *      PT: 48657920426F622C206974277320416C696365
 *      CT: 92994326C5A45DECBB49A438928F171C5423BF53F199B9A631C64FF7F5DE8D9C5A10A107B71BDE5D23C0719F4B32BD9D8FDB40E21459EE4E3303F04DCA5BD330C47430970FB9D22E6788BEC7EE7980B2FD1F7E73ABAEB7AB20D701A5C40781C447F177764F618E3B0BFB551438ED29EC02AA499366179FCE0E6F0A564EC7710F
 *      PT: 48657920426F622C206974277320416C696365
 *
 * We can also create our custom private key with a modulus and exponent (https://stackoverflow.com/questions/41584629/rsa-encryption-using-modulus-and-exponent-in-java)
 */
public class RSA_ECB {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Environment env = new Environment();

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                byte[] plaintext = "Hey Bob, it's Alice".getBytes(StandardCharsets.UTF_8);

                System.out.println("PT to Bob: " + Agent.hex(plaintext));

                final Cipher encryption = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");

                encryption.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());

                byte[] ciphertext = encryption.doFinal(plaintext);

                System.out.println("CT to Bob: " + Agent.hex(ciphertext));

                send("bob", ciphertext);

                /*
                    Receive message from Bob
                 */

                ciphertext = receive("bob");

                encryption.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());

                plaintext = encryption.doFinal(ciphertext);

                System.out.println("PT from Bob: " + Agent.hex(plaintext));

                print(new String(plaintext, StandardCharsets.UTF_8));
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                byte[] ciphertext = receive("alice");

                final Cipher encryption = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");

                encryption.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());

                byte[] plaintext = encryption.doFinal(ciphertext);

                System.out.println("PT from Alice: " + Agent.hex(plaintext));

                print(new String(plaintext, StandardCharsets.UTF_8));

                /*
                    Send message to Alice
                 */

                plaintext = "Hey Alice, it's Bob".getBytes(StandardCharsets.UTF_8);

                System.out.println("PT to Alice: " + Agent.hex(plaintext));

                encryption.init(Cipher.ENCRYPT_MODE, aliceKP.getPublic());

                ciphertext = encryption.doFinal(plaintext);

                System.out.println("CT to Alice: " + Agent.hex(ciphertext));

                send("alice", ciphertext);
            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    /*
        Example taken from stack overflow (https://stackoverflow.com/questions/41584629/rsa-encryption-using-modulus-and-exponent-in-java)
        Here we see how to manually create a private key using a custom modulus and exponent
     */
    private static PrivateKey createPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicModulus = "d2c34017ef94f8ab6696dae66e3c0d1ad186bbd9ce4461b68d7cd017c15bda174045bfef36fbf048" +
                "73cfd6d09e3806af3949f99c3e09d6d3c37f6398d8c63f9a3e39b78a187809822e8bcf912f4c44a8" +
                "92fe6a65a477ddea9582738317317286a2610ba30b6b090c3b8c61ffb64207229b3f01afe928a960" +
                "c5a44c24b26f5f91";

        String privateExponent = "6c97ab6369cf00dd174bacd7c37e6f661d04e5af10670d4d88d30148ec188e63227b8dac0c517cf9" +
                "67aa73cd23684c9165dc269f091bfab33b6c5c7db95b54130e348255c30aaaac1c7f09ef701e0d6f" +
                "6dc142d2e4ed78466cc104e28d50be7adf3863afc021dbdd8b5f0b968b7cd965242c7d8d4b32ee84" +
                "0fac3cad134344c1";

        BigInteger privateExponenInt = new BigInteger(privateExponent, 16);

        BigInteger keyInt = new BigInteger(publicModulus, 16);

        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(keyInt, privateExponenInt);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        return factory.generatePrivate(privateKeySpec);
    }
}