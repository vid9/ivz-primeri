package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.Key;

public class RC4 {
    public static String[] METHOD = {"RC4", "RC4"};

    public static void main(String[] args) throws Exception {
        //STEP 1: CREATE COMMON KEY
        final Key key = KeyGenerator.getInstance(METHOD[0]).generateKey();

        //STEP 2: SETUP COMMUNICATION
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                //STEP 3: CREATE MESSAGE, ENCRYPT IT AND SEND IT
                String message = "Hello Bob, this is confidential message. Regards, Alice.";
                System.out.println("[MESSAGE] " +  message);

                final byte[] plainText = message.getBytes();
                System.out.println("[PT] " + hex(plainText));

                final Cipher encryption = Cipher.getInstance(METHOD[1]);
                encryption.init(Cipher.ENCRYPT_MODE, key);
                final byte[] cipherText = encryption.doFinal(plainText);
                System.out.println("[CT] " + hex(cipherText));

                send("bob", cipherText);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // STEP 4: RECEIVE MESSAGE, DECRYPT IT
                final byte[] receivedCipherText = receive("alice");
                System.out.println("[CT] " + hex(receivedCipherText));

                final Cipher decryption = Cipher.getInstance(METHOD[1]);
                decryption.init(Cipher.DECRYPT_MODE, key);
                final byte[] receivedPlainText = decryption.doFinal(receivedCipherText);
                System.out.println("[PT] " + hex(receivedPlainText));

                System.out.println("[MESSAGE] " + new String(receivedPlainText));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}