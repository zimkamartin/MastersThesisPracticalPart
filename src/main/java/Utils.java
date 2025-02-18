import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.fips202.Shake128;
import com.swiftcryptollc.crypto.provider.kyber.Poly;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class Utils {

    public static byte[] shortArrayToByteArray(short[] shorts) {  // generated by ChatGPT
        byte[] bytes = new byte[shorts.length * 2]; // Each short = 2 bytes
        for (int i = 0; i < shorts.length; i++) {
            bytes[i * 2] = (byte) (shorts[i] >> 8);  // High byte
            bytes[i * 2 + 1] = (byte) (shorts[i]);   // Low byte
        }
        return bytes;
    }

    public static short[] byteArrayToShortArray(byte[] byteArray) {  // generated by ChatGPT
        // Make sure the byte array length is even for proper conversion to short[]
        if (byteArray.length % 2 != 0) {
            throw new IllegalArgumentException("Byte array length must be even for short array conversion.");
        }
        // Create an array of shorts with half the length of the byte array
        short[] shortArray = new short[byteArray.length / 2];
        // Loop through byte array and convert pairs of bytes to shorts
        for (int i = 0; i < byteArray.length; i += 2) {
            // Combine two bytes into one short
            shortArray[i / 2] = (short) (((byteArray[i] & 0xFF) << 8) | (byteArray[i + 1] & 0xFF));
        }
        return shortArray;
    }

    public static byte[] concatByteArrays(byte[] first, byte[] second) {  // generated by ChatGPT
        // Create a new array to hold both byte arrays
        byte[] concatenatedArray = new byte[first.length + second.length];
        // Copy the first array into the new array
        System.arraycopy(first, 0, concatenatedArray, 0, first.length);
        // Copy the second array into the new array
        System.arraycopy(second, 0, concatenatedArray, first.length, second.length);
        // Print concatenated array
        return concatenatedArray;
    }

    public static short[] createShortArrayFromInt(int value, int n) {  // generated by ChatGPT
        // Check if the int value is within the range of short (-32768 to 32767)
        if (value < Short.MIN_VALUE || value > Short.MAX_VALUE) {
            throw new IllegalArgumentException("Value is out of the range for short: " + value);
        }
        // Create the short array of size 'n'
        short[] shortArray = new short[n];
        // Fill the array with the given value (cast the int to short)
        Arrays.fill(shortArray, (short) value);
        return shortArray;
    }

    public static int ACon(double k1, double sigma1, double q, double m, double g) {
        // round(sigma_1 * q / m)
        long roundedTerm = Math.round(sigma1 * q / m);
        // floor(g(k_1 + roundedTerm) / q)
        long flooredTerm = (long) Math.floor(g * (k1 + roundedTerm) / q);
        return (int) (flooredTerm % g);
    }

    public static int ARec(double k2, double v, double q, double m, double g) {
        // floor(m * (v / g - k_2 / q))
        long flooredTerm = (long) Math.floor(m * (v / g - k2 / q));
        return (int) (flooredTerm % m);
    }

    public static double bytesToDouble(byte[] bytes) {  // generated by ChatGPT
        return ByteBuffer.wrap(bytes).getDouble();
    }

    public static byte[] intToByteArray(int input) {  // generated by ChatGPT
        return ByteBuffer.allocate(4).putInt(input).array();
    }

    public static void fillWithCBD(short[][] toFill, byte[] noiseSeed, int paramsK) {  // extracted rows 267 - 275 from
    // https://github.com/fisherstevenk/kyberJCE/blob/main/src/main/java/com/swiftcryptollc/crypto/provider/kyber/Indcpa.java
        byte nonce = (byte) 0;
        for (int i = 0; i < paramsK; i++) {
            toFill[i] = Poly.getNoisePoly(noiseSeed, nonce, paramsK);
            nonce = (byte) (nonce + (byte) 1);
        }
    }

    public static byte[] nBytesFromShake128(byte[] input, int n) {
        byte[] output = new byte[n];
        KeccakSponge xof = new Shake128();
        xof.reset();
        xof.getAbsorbStream().write(input);
        xof.getAbsorbStream().close();

        int bytesRead = 0;  // generated by ChatGPT
        while (bytesRead < output.length) {
            int result = xof.getSqueezeStream().read(output, bytesRead, output.length - bytesRead);
            if (result == -1) break;  // EOF (should not happen in SHAKE)
            bytesRead += result;
        }

        return output;
    }
}
