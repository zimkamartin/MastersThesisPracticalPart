import com.swiftcryptollc.crypto.provider.KyberJCE;
import com.swiftcryptollc.crypto.provider.KyberPackedPKI;

import java.security.Security;
import java.util.Arrays;

import static com.swiftcryptollc.crypto.provider.kyber.Indcpa.generateKyberKeys;
import static com.swiftcryptollc.crypto.provider.kyber.Poly.*;
import static java.lang.Math.abs;
import static java.lang.Math.round;

public class Main {
    public static void main(String[] args) {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new KyberJCE());

        authenticatedKeyExchange();

        System.out.print("Everything went well...");

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

    private static void authenticatedKeyExchange() {

        try {

            // KEY -> (s_1, p_i) // client //

            int paramsK = 4;
            KyberPackedPKI keysClient = generateKyberKeys(paramsK);
            byte[] piC = keysClient.getPackedPublicKey();

            // KEY -> (s_1', p_j) // server //

            KyberPackedPKI keysServer = generateKyberKeys(paramsK);
            byte[] pjS = keysServer.getPackedPublicKey();

            // p_i' = Compress_q(p_i, d_u) // client //

            int du = 11;
            byte[] piPrime = compressPoly(Utils.byteArrayToShortArray(piC), du);

            // Send i, p_i' to the server. //

            // p_i = Decompress_q(p_i', d_u) // server //

            short[] piS = decompressPoly(piPrime, du);


        } catch (Exception ex) {
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
    }
}