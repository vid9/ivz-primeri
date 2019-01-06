package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * A communication channel is implemented with thread-safe blocking queue.
 * <p/>
 * Both agents are implemented by extending the Agents class,
 * creating anonymous class and overriding #execute().
 * <p/>
 * Both agents are started at the end of the main method definition below.
 */
public class AgentCommunication {
    public static void main(String[] args) {
        final Environment env = new Environment();

       env.add(new Agent("Alice") {
           @Override
           public void task() throws Exception {
               print("Hello World!");
               final byte[] message = "Hi Bob, this is Alice".getBytes();
               send("Bob", message);
           }
       });

       env.add(new Agent("Bob") {
           @Override
           public void task() throws Exception {
               print("Hello world!");
               final byte[] fromAlice = receive("Alice");
               print("I got: '%s'", new String(fromAlice));
           }
       });

       env.add(new Agent("Mallory") {
           @Override
           public void task() throws Exception {
               print("Hello world");
               byte[] fromAlice = receive("Alice");
               send("Bob", fromAlice);
               print("I'am forwarding: '%s'", new String(fromAlice));

           }
       });

        //env.connect("Alice", "Bob");
        env.mitm("Alice","Bob","Mallory");
        env.start();
    }
}
