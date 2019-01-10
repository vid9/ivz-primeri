package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/*
    Introduction
        The goal of this challenge is to demonstrate that ciphertexts are vulnerable to modifications and that in many cases
        these modifications have (painfully) predictable effect on the plaintext. This should motivate you to learn about
        integrity and authenticated encryption that we’ll cover in the upcoming week.
        If we know the cipher text beforehand, we can easily change the output plaint text, that's why wee ned integrity and
        authenticated encryption
            Integrity: we know that the message was not changed in any way during it's trip
            Authentication: we know which entity sent the message
    Motivation
        As the motivating example, consider the following scenario.
        A teaching assistant David wants to send a highly confidential email to professor Denis, most likely containing
        questions for the upcoming exam. Needless to say, you are very interested in seeing the contents of that email.
        Luckily, a few things go your way.
        First, David has no Internet connectivity, but your brand new mobile phone does. So you kindly offer to set-up a
        mobile hot-spot through which David will be able to connect to an SMTP server. (You get to play the role of the
        man-in-the-middle for free!)
        Second, David is using a simplified version of the SMTP protocol: all that David’s mail client has to do to send an e
        mail, is to deliver the following string to the SMTP server.
        from: ta.david@fri.uni-lj.si
        to: prof.denis@fri.uni-lj.si
        <The contents of the email>
        Third, David is naive enough to tell you that he’s sending the email to professor Denis. (So you know what the
        contents of the first two lines of the plaintext are.)
        Fourth, David is using AES in counter-mode. No integrity checks are in place.
    Assignment
        As the man-in-the-middle (MITM), modify the ciphertext so that the SMTP server will not send the email to professor
         Denis, but instead will forward the email to the address of your choice (that would probably be your email address).
        You can assume that the new email address has either the same length as the professor’s or its length is shorter.
 */

public class Homework_1 {
    public static void main(String[] args) throws Exception {
        // David and SMTP server both know the same shared secret key
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("david") {
            @Override
            public void task() throws Exception {
                final String message = "from: ta.david@fri.uni-lj.si\n" +
                        "to: prof.denis@fri.uni-lj.si\n\n" +
                        "Hi! Find attached <some secret stuff>!";

                final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");

                aes.init(Cipher.ENCRYPT_MODE, key);

                final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));

                final byte[] iv = aes.getIV();

                print("sending: '%s' (%s)", message, hex(ct));

                send("server", ct);
                send("server", iv);
            }
        });

        env.add(new Agent("student") {
            @Override
            public void task() throws Exception {
                final byte[] receivedMessage = receive("david");
                final byte[] iv = receive("david");

                print(" IN: %s", hex(receivedMessage));

                // As the person-in-the-middle, modify the ciphertext
                // so that the SMTP server will send the email to you
                // (Needless to say, you are not allowed to use the key
                // that is being used by david and server.)

                String senderText = "from: ta.david@fri.uni-lj.si\nto: ";
                String receiverText = "prof.denis@fri.uni-lj.si";

                byte[] receiverBytes = receiverText.getBytes();

                String maliciousText = "np9417@student.uni-lj.si";
                byte[] maliciousBytes = maliciousText.getBytes();

                // Start your malicious for loop at the "from: ... to:" ending index
                for (int i = senderText.length(); i < senderText.length() + receiverText.length(); i++) {
                    // By xor-ing we get the key for this particular byte
                    // We are xor-ing the cipher text with "prof.denis@fri.uni-lj.si"
                    receivedMessage[i] = (byte) ((int) receiverBytes[i - senderText.length()] ^ (int) receivedMessage[i]);

                    // Here we simply xor the key for this byte with our malicious byte
                    // We are xor-ing the key with "np9417@student.uni-lj.si"
                    receivedMessage[i] = (byte) ((int) maliciousBytes[i - senderText.length()] ^ (int) receivedMessage[i]);
                }

                print("OUT: %s", hex(receivedMessage));
                send("server", receivedMessage);
                send("server", iv);
            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                final byte[] ct = receive("david");
                final byte[] iv = receive("david");
                final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                final byte[] pt = aes.doFinal(ct);
                final String message = new String(pt, StandardCharsets.UTF_8);

                print("got: '%s' (%s)", message, hex(ct));
            }
        });

        env.mitm("david", "server", "student");

        env.start();
    }
}