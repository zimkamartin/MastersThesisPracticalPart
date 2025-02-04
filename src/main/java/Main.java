import com.swiftcryptollc.crypto.provider.KyberJCE;
import com.swiftcryptollc.crypto.provider.KyberUniformRandom;
import com.swiftcryptollc.crypto.provider.kyber.KyberParams;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import static com.swiftcryptollc.crypto.provider.kyber.Indcpa.generateUniform;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        System.out.print("Just some print 01.");

        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new KyberJCE());

        // Alice generates a KeyPair and sends her public key to Bob
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber1024");
        System.out.print("Just some print 02.");

        establishValidator();

    }

    private static void establishValidator() {
        try {

            // seed <- R_q //

            // Create random input of bytes for generateUniform
            byte[] seedGU = new byte[504];
            SecureRandom sr = SecureRandom.getInstanceStrong();
            sr.nextBytes(seedGU);

            KyberUniformRandom uniformRandom = new KyberUniformRandom();
            generateUniform(uniformRandom, seedGU, 504, KyberParams.paramsN);

            short[] seed = uniformRandom.getUniformR();  // length = 384 because of KyberParams.paramsPolyBytes

        } catch (Exception ex) {
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
    }
}