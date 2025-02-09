import com.swiftcryptollc.crypto.provider.KyberJCE;
import com.swiftcryptollc.crypto.provider.KyberPackedPKI;

import java.security.Security;
import java.util.Arrays;

import static com.swiftcryptollc.crypto.provider.kyber.Indcpa.generateKyberKeys;
import static com.swiftcryptollc.crypto.provider.kyber.Poly.*;

public class Main {
    public static void main(String[] args) {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new KyberJCE());

        authenticatedKeyExchange();

        System.out.print("Everything went well...");

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