import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.fips202.Shake128;
import com.swiftcryptollc.crypto.provider.KyberJCE;
import com.swiftcryptollc.crypto.provider.KyberUniformRandom;
import com.swiftcryptollc.crypto.provider.kyber.KyberParams;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import static com.swiftcryptollc.crypto.provider.kyber.Indcpa.generateUniform;

public class Main {
    public static void main(String[] args) {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new KyberJCE());

        establishValidator();

        System.out.print("Everything went well...");

    }

    private static void establishValidator() {
        try {

            // seed <- R_q //

            // Create random input of bytes for generateUniform
            byte[] seedGU = new byte[504];  // NO idea what should be the size
            SecureRandom sr = SecureRandom.getInstanceStrong();
            sr.nextBytes(seedGU);

            // Use generateUniform = equivalent of Parse in official Kyber:
            // "Kyber uses a deterministic approach to sample elements in Rq that are statistically close
            // to a uniformly random distribution. For this sampling we use a function Parse"
            KyberUniformRandom uniformRandom = new KyberUniformRandom();
            generateUniform(uniformRandom, seedGU, 504, KyberParams.paramsN);

            short[] seed = uniformRandom.getUniformR();  // length = 384 because of KyberParams.paramsPolyBytes

            // a = SHAKE-128(seed) //

            byte[] buf = new byte[64];  // NO idea what should be the size

            KeccakSponge xof = new Shake128();
            xof.reset();
            xof.getAbsorbStream().write(Utils.shortArrayToByteArray(seed));
            xof.getSqueezeStream().read(buf);

        } catch (Exception ex) {
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
    }
}