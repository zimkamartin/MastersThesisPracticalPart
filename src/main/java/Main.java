import com.swiftcryptollc.crypto.provider.KyberJCE;
import com.swiftcryptollc.crypto.provider.KyberPackedPKI;
import com.swiftcryptollc.crypto.provider.kyber.KyberParams;

import java.security.Security;
import java.util.Arrays;

import static com.swiftcryptollc.crypto.provider.kyber.Indcpa.generateKyberKeys;
import static com.swiftcryptollc.crypto.provider.kyber.Poly.*;
import static java.lang.Math.*;

public class Main {
    public static void main(String[] args) {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new KyberJCE());

        // CompressDecompress();

        AConARec();

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

    private static void CompressDecompress() {

        try {

            // KEY -> (s_1, p_i) // client //

            int paramsK = 4;
            KyberPackedPKI keysClient = generateKyberKeys(paramsK);
            byte[] piC = keysClient.getPackedPublicKey();

            // p_i' = Compress_q(p_i, d_u) // client //

            int du = 11;
            byte[] piPrime = compressPoly(Utils.byteArrayToShortArray(piC), du);
            System.out.println(checkCompressOutput(piPrime, KyberParams.paramsQ));

            // p_i = Decompress_q(p_i', d_u) // server //

            short[] piS = decompressPoly(piPrime, du);

            System.out.println(Arrays.toString(piC));
            System.out.println(Arrays.toString(piS));


        } catch (Exception ex) {
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
    }

    public static long ACon(double k1, double sigma1, double q, double m, double g) {
        // round(sigma_1 * q / m)
        long roundedTerm = Math.round(sigma1 * q / m);
        // floor(g(k_1 + roundedTerm) / q)
        long flooredTerm = (long) Math.floor(g * (k1 + roundedTerm) / q);
        long lG = (long) g;
        return ((flooredTerm % lG) + lG) % lG;  // ((a % q) + q) % q; to have always positive result
    }

    public static long ARec(double k2, double v, double q, double m, double g) {
        // floor(m * (v / g - k_2 / q))
        long flooredTerm = (long) Math.floor(m * (v / g - k2 / q));
        long lM = (long) m;
        return ((flooredTerm % lM) + lM) % lM;  // ((a % q) + q) % q; to have always positive result
    }

    private static void AConARec() {
        double k1 = 1.0;  // k1 and k2 selected the same so that |k_i - k_j| <= d holds (found in KSRP 5.1)
        double k2 = 1.0;
        double q = 12289.0;  // q, m, g taken from KSRP 5.1
        double m = 16.0;
        double g = 256.0;

        long nu;
        long sigma2;

        int numOfSameSigmas = 0;

        for (double sigma1 = 0; sigma1 < m; sigma1 += 1) {
            nu = ACon(k1, sigma1, q, m, g);
            sigma2 = ARec(k2, (double) nu, q, m, g);

            numOfSameSigmas += (sigma1 == sigma2) ? 1 : 0;

            System.out.println(sigma1);
            System.out.println(sigma2);
            System.out.println("###");
        }
        System.out.println(numOfSameSigmas / m);
    }
}