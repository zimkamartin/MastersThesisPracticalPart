import com.swiftcryptollc.crypto.provider.KyberJCE;
import com.swiftcryptollc.crypto.provider.KyberPackedPKI;
import com.swiftcryptollc.crypto.provider.kyber.KyberParams;
import com.swiftcryptollc.crypto.provider.kyber.Poly;

import java.security.Security;

import static com.swiftcryptollc.crypto.provider.kyber.Indcpa.generateKyberKeys;
import static java.lang.Math.*;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Main {
    public static void main(String[] args) {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new KyberJCE());

        // compressDecompress();

        aConARec();

        System.out.print("Everything went well...");

    }

    public static double log(double base, double x) {  // implemented by ChatGPT
        return Math.log(x) / Math.log(base);
    }

    private static boolean checkCompressOutput(byte[] compressed, int q) {
        int d = (int) ceil(log(2, q)) - 1;
        for (byte c : compressed) {
            int cInt = (int) c;
            if (cInt < 0 || (2^d) < cInt) {
                System.out.println(cInt);
                return false;
            }
        }
        return true;
    }

    // Based on the Kyber's documentation, the following must hold for functions Compress and Decompress:
    // x' = Decompress_q(Compress_q(x, d), d)
    // |x' - x mod^± q| ≤ round(q / w^(d+1)).
    // Where for an even (resp. odd) positive integer \alpha, we define r' = r mod± \alpha to be the unique
    // element r' in the range −\alpha/2 < r' ≤ \alpha/2 (resp. −(\alpha-1)/2 ≤ r' ≤ (\alpha-1)/2)
    // such that r' = r mod \alpha.
    private static boolean checkCompDecompResultCodition(int x, int xPrime, int d, int q) {
        int leftSide;
        int mod = (xPrime - x) % q;
        if (q % 2 == 0 && mod > q/2) {  // q is even and ...
            leftSide = abs(mod - q);
        } else if (q % 2 == 1 && mod > (q-1)/2) {
            leftSide = abs(mod - q);
        } else {
            leftSide = abs(mod);
        }
        int rightSide = round((float) q / (2^(d+1)));
        return leftSide <= rightSide;
    }

    private static byte[] compressPoly3(short[] polyA) {

        byte[] t = new byte[8];
        polyA = Poly.polyConditionalSubQ(polyA);
        int rr = 0;
        byte[] r;

        r = new byte[KyberParams.paramsPolyCompressedBytesK1024];  // why 160?
        for (int i = 0; i < KyberParams.paramsN / 8; i++) {
            for (int j = 0; j < 8; j++) {
                t[j] = (byte) (((((polyA[8 * i + j]) << 3) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ)) & 7);
            }  // TODO: change following rows
            r[rr + 0] = (byte) ((t[0] >> 0) | (t[1] << 5));
            r[rr + 1] = (byte) ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
            r[rr + 2] = (byte) ((t[3] >> 1) | (t[4] << 4));
            r[rr + 3] = (byte) ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
            r[rr + 4] = (byte) ((t[6] >> 2) | (t[7] << 3));
            rr = rr + 5;
        }

        return r;
    }

    private static void compressDecompress() {

        try {

            KyberPackedPKI keys = generateKyberKeys(4);
            byte[] compressed = compressPoly3(new short[1]);

        } catch (Exception ex) {
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
    }

    public static long aCon(double k1, double sigma1, double q, double m, double g) {
        // round(sigma_1 * q / m)
        long roundedTerm = Math.round(sigma1 * q / m);
        // floor(g(k_1 + roundedTerm) / q)
        long flooredTerm = (long) Math.floor(g * (k1 + roundedTerm) / q);
        long lG = (long) g;
        return ((flooredTerm % lG) + lG) % lG;  // ((a % q) + q) % q; to have always positive result
    }

    public static long aRec(double k2, double v, double q, double m, double g) {
        // floor(m * (v / g - k_2 / q))
        long flooredTerm = (long) Math.floor(m * (v / g - k2 / q));
        long lM = (long) m;
        return ((flooredTerm % lM) + lM) % lM;  // ((a % q) + q) % q; to have always positive result
    }

    private static void aConARec() {
        long counter = 0;
        System.out.println("Testing all possibilities sigma1 for ACon and ARec.");

        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());  // to be sure, that name of a file is unique
        String fileName = timestamp + ".txt";

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName))) {  // Write same outputs as inputs to a file.

            int numOfSameSigmas = 0;

            double q = 12289.0;  // q, m, g taken from KSRP 5.1
            double m = 16.0;
            double g = 256.0;
            double d = 509.0;

            long nu;
            long sigma2;

            for (int k1 = 0; k1 < q; k1++) {  // goes through all possibilities for k1 and k2. Both params are from Z_q.
                for (int k2 = 0; k2 < q; k2++) {

                    if (abs(k1 - k2) > d) {  // From paper: "Thence, |k_i − k_j| <= d, i.e., equation sk_i = sk_j holds in the protocol proposed in this paper."
                        continue;
                    }

                    int numOfSameSigmasInRound = 0;

                    for (double sigma1 = 0; sigma1 < m; sigma1 += 1) {
                        nu = aCon(k1, sigma1, q, m, g);
                        sigma2 = aRec(k2, (double) nu, q, m, g);

                        if (sigma1 == sigma2) {
                            numOfSameSigmasInRound += 1;
                            String k = String.format("K1 = %d. K2 = %d. ", k1, k2);
                            String s1 = String.format("Sigma1 = %d. ", (long) sigma1);
                            String s2 = String.format("Sigma2 = %d.%n", sigma2);

                            writer.write(k);
                            writer.write(s1);
                            writer.write(s2);
                        }
                        counter += 1;
                    }
                    numOfSameSigmas += numOfSameSigmasInRound;
                }
            }

            writer.newLine();
            String stats = String.format("From %d sigmas %d was the same as an input, so that is %f percent.%n%n", counter, numOfSameSigmas, (double) numOfSameSigmas * 100 / counter);
            writer.write(stats);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}