package isp.handson;

import sun.security.util.BitArray;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.imageio.ImageIO;
import javax.xml.bind.DatatypeConverter;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.BitSet;

/**
 * Assignments:
 * <p>
 * 1. Change the encoding process, so that the first 4 bytes of the steganogram hold the
 * length of the payload. Then modify the decoding process accordingly.
 * 2. Add security: Provide secrecy and integrity for the hidden message. Use GCM for cipher.
 * Also, use AEAD to provide integrity to the steganogram size.
 * 3. Extra: Enhance the capacity of the carrier:
 * -- Use the remaining two color channels;
 * -- Use additional bits.
 */
public class ImageSteganography {

    public static void main(String[] args) throws Exception {
        final byte[] payload = "My secret message".getBytes(StandardCharsets.UTF_8);

        ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram.png");
        final byte[] decoded = ImageSteganography.decode("images/steganogram.png", payload.length+4);
        System.out.printf("Decoded: %s%n", new String(decoded, StandardCharsets.UTF_8));


        //TODO: Assignment 1
        ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram.png");
        final byte[] decoded1 = ImageSteganography.decode("images/steganogram.png", payload.length+4);
        System.out.printf("Decoded: %s%n", new String(decoded1, "UTF-8"));

/*
        //TODO: Assignment 2
        final SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        ImageSteganography.encryptAndEncode(payload, "images/2_Morondava.png", "images/steganogram-encrypted.png", key);
        final byte[] decoded2 = ImageSteganography.decryptAndDecode("images/steganogram-encrypted.png", key);

        System.out.printf("Decoded: %s%n", new String(decoded2, "UTF-8"));*/
    }

    /**
     * Encodes given payload into the cover image and saves the steganogram.
     *
     * @param pt      The payload to be encoded
     * @param inFile  The filename of the cover image
     * @param outFile The filename of the steganogram
     * @throws IOException If the file does not exist, or the saving fails.
     */
    public static void encode(final byte[] pt, final String inFile, final String outFile) throws IOException {
        // load the image
        final BufferedImage image = loadImage(inFile);

        //pt = len(pt) + pt
        ByteBuffer.allocate(4+pt.length)
                            .putInt(pt.length)
                            .put(pt)
                            .array();

        // Convert byte array to bit sequence
        final BitSet bits = BitSet.valueOf(pt);

        // encode the bits into image
        encode(bits, image);

        // save the modified image into outFile
        saveImage(outFile, image);
    }

    /**
     * Decodes the message from given filename.
     *
     * @param fileName The name of the file
     * @return The byte array of the decoded message
     * @throws IOException If the filename does not exist.
     */
    public static byte[] decode(final String fileName, int size) throws IOException {
        // load the image
        final BufferedImage image = loadImage(fileName);

        // read all LSBs
        final BitArray bits = decode(image, size);

        // convert them to bytes
        return bits.toByteArray();
    }

    /**
     * Encrypts and encodes given plain text into the cover image and then saves the steganogram.
     *
     * @param pt      The plaintext of the payload
     * @param inFile  cover image filename
     * @param outFile steganogram filename
     * @param key     symmetric secret key
     * @throws Exception
     */
    public static void encryptAndEncode(final byte[] pt, final String inFile, final String outFile, final Key key)
            throws Exception {
        // TODO
    }

    /**
     * Decrypts and then decodes the message from the steganogram.
     *
     * @param fileName name of the steganogram
     * @param key      symmetric secret key
     * @return plaintext of the decoded message
     * @throws Exception
     */
    public static byte[] decryptAndDecode(final String fileName, final Key key) throws Exception {
        // TODO
        return null;
    }

    /**
     * Loads an image from given filename and returns an instance of the BufferedImage
     *
     * @param inFile filename of the image
     * @return image
     * @throws IOException If file does not exist
     */
    protected static BufferedImage loadImage(final String inFile) throws IOException {
        return ImageIO.read(new File(inFile));
    }

    /**
     * Saves given image into file
     *
     * @param outFile image filename
     * @param image   image to be saved
     * @throws IOException If an error occurs while writing to file
     */
    protected static void saveImage(String outFile, BufferedImage image) throws IOException {
        ImageIO.write(image, "png", new File(outFile));
    }

    /**
     * Encodes bits into image. The algorithm modifies the least significant bit
     * of the red RGB component in each pixel.
     *
     * @param payload Bits to be encoded
     * @param image   The image onto which the payload is to be encoded
     */
    protected static void encode(final BitSet payload, final BufferedImage image) {
        for (int x = image.getMinX(), bitCounter = 0; x < image.getWidth() && bitCounter < payload.size(); x++) {
            for (int y = image.getMinY(); y < image.getHeight() && bitCounter < payload.size(); y++) {
                final Color original = new Color(image.getRGB(x, y));

                // Let's modify the red component only
                final int newRed = payload.get(bitCounter) ?
                        original.getRed() | 0x01 : // sets LSB to 1
                        original.getRed() & 0xfe;  // sets LSB to 0

                // Create a new color object
                final Color modified = new Color(newRed, original.getGreen(), original.getBlue());

                // Replace the current pixel with the new color
                image.setRGB(x, y, modified.getRGB());

                // Uncomment to see changes in the RGB components
                // System.out.printf("%03d bit [%d, %d]: %s -> %s%n", bitCounter, i, j, original, modified);

                bitCounter++;
            }
        }
    }

    /**
     * Decodes the message from the steganogram
     *
     * @param image steganogram
     * @param size  the size of the encoded steganogram
     * @return {@link BitSet} instance representing the sequence of read bits
     */
    protected static BitArray decode(final BufferedImage image, int size) {
        int payloadSize = size*8;
        BitArray bits = new BitArray(payloadSize);

        String bitsString = "";

        int minX = image.getMinX();
        int minY = image.getMinY();

        int width = image.getWidth();
        int height = image.getHeight();

        boolean foundLength = false;

        for (int x = minX, indexOfCurrentBit = 0; x < width && indexOfCurrentBit < payloadSize - 1; x++) {
            for (int y = minY; y < height && indexOfCurrentBit < payloadSize - 1; y++) {
                int pixelValue = image.getRGB(x, y);

                Color color = new Color(pixelValue);

                int[] colors = new int[] {
                        color.getRed(),
                        color.getGreen(),
                        color.getBlue()
                };

                for (int singleColor : colors) {
                    if (getLeastSignificantBitFromColor(singleColor)) bitsString += "1";
                    else bitsString += "0";

                    bits.set(indexOfCurrentBit, getLeastSignificantBitFromColor(singleColor));

                    // We only need to process the image until all the payload values are encoded
                    if (indexOfCurrentBit < payloadSize - 1) indexOfCurrentBit++;
                    else if (!foundLength) {
                        // We processed the first 4 bytes, now we get the size
                        payloadSize = bitsToInt(bits) * 8;

                        foundLength = true;

                        indexOfCurrentBit = 0;

                        bits = new BitArray(payloadSize);
                    }
                }
            }
        }

        return bits;
    }

    protected static int setLeastSignificantBitForColor(int colorValue, boolean payloadBit) {
        if (payloadBit) {
            // 0x01 = 00000001 -> use bitwise OR with this value to only set the LSB to 1
            colorValue = colorValue | 0x01;
        } else {
            // 0xfe = 11111110 -> use bitwise AND with this value to only set the LSB to 0
            colorValue = colorValue & 0xfe;
        }

        return colorValue;
    }


    protected static boolean getLeastSignificantBitFromColor(int colorValue) {
        // 0x01 = 00000001 -> use bitwise AND with this value to check if the LSB is either 0 or 1
        return (colorValue & 0x01) != 0;
    }

    public static int bitsToInt(BitArray bitArray) {
        int integerFromBits = 0;

        for (int i = 0; i < 32; i++) {
            if (bitArray.get(i)) {
                // This particular bit is on

                integerFromBits = integerFromBits | (1 << (32 - i - 1));
            }
        }

        return integerFromBits;
    }
}


