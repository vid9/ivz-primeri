package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class HandsOnAssignment {
    public static void main(String[] args) throws NoSuchAlgorithmException {

        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                
                final byte[] dataForBob = "Hey Bob, it's Alice".getBytes(StandardCharsets.UTF_8);
                send("bob", dataForBob);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final byte[] dataFromAlice = receive("alice");
                print("Got '%s'", new String(dataFromAlice, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
