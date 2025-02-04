import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.fips202.Shake128;
import com.swiftcryptollc.crypto.provider.KyberJCE;
import com.swiftcryptollc.crypto.provider.KyberUniformRandom;
import com.swiftcryptollc.crypto.provider.kyber.KyberParams;

import java.security.MessageDigest;
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

            byte[] a = new byte[64];  // NO idea what should be the size

            KeccakSponge xof = new Shake128();
            xof.reset();
            xof.getAbsorbStream().write(Utils.shortArrayToByteArray(seed));
            xof.getSqueezeStream().read(a);

            // seed1 = H(salt || H(I || pwd)) //

            String i = "identity123";
            String pwd = "password123";
            String iPwdConcatenated = i.concat(pwd);

            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            byte[] hIntermediate = md.digest(iPwdConcatenated.getBytes());

            // Create random input of bytes for generateUniform
            byte[] salt = new byte[64];  // NO idea what should be the size
            sr.nextBytes(salt);

            md.reset();
            byte[] seed1 = md.digest(Utils.concatByteArrays(salt, hIntermediate));

            // seed2 = H(seed1) //

            md.reset();
            byte[] seed2 = md.digest(seed1);



        } catch (Exception ex) {
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
    }
}