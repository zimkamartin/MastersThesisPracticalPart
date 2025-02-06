import com.github.aelstad.keccakj.core.KeccakSponge;
import com.github.aelstad.keccakj.fips202.Shake128;
import com.swiftcryptollc.crypto.provider.KyberJCE;
import com.swiftcryptollc.crypto.provider.KyberPackedPKI;
import com.swiftcryptollc.crypto.provider.KyberUniformRandom;
import com.swiftcryptollc.crypto.provider.kyber.KyberParams;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import static com.swiftcryptollc.crypto.provider.kyber.Indcpa.generateKyberKeys;
import static com.swiftcryptollc.crypto.provider.kyber.Indcpa.generateUniform;
import static com.swiftcryptollc.crypto.provider.kyber.Poly.*;

public class Main {
    public static void main(String[] args) {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new KyberJCE());

        short[] v = establishValidator();

        authenticatedKeyExchange(v);

        System.out.print("Everything went well...");

    }

    private static short[] establishValidator() {

        // Everything is on the client's side.

        short[] v = new short[64];  // NO idea what should be the size

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

            byte[] a = Utils.nBytesFromShake128(Utils.shortArrayToByteArray(seed), 2 * KyberParams.paramsPolyBytes);

            // seed1 = H(salt || H(I || pwd)) //

            String i = "identity123";
            String pwd = "password123";
            String iPwdConcatenated = i.concat(pwd);

            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            byte[] intermediateHash = md.digest(iPwdConcatenated.getBytes());

            // Create random input of bytes for generateUniform
            byte[] salt = new byte[64];  // NO idea what should be the size
            sr.nextBytes(salt);

            md.reset();
            byte[] seed1 = md.digest(Utils.concatByteArrays(salt, intermediateHash));

            // seed2 = H(seed1) //

            md.reset();
            byte[] seed2 = md.digest(seed1);

            // s_v <- PRNG(seed1) // WHAT should be PRNG? If Discrete Gaussian distribution, then how to use it?
            // also because of the computation of v, s_v should be \in R_q and use polyBaseMulMont

            int sv = sr.nextInt();  // FIX it

            // e_v <- PRNG(seed1) // WHAT should be PRNG? If Discrete Gaussian distribution, then how to use it?
            // also because of the computation of v, e_v should be \in R_q and use polyBaseMulMont

            int ev = sr.nextInt();  // FIX it

            // v <- as_v + e_v \in R_q //

            short[] aShort = Utils.byteArrayToShortArray(a);
            sv = sv % Short.MAX_VALUE;
            ev = ev % Short.MAX_VALUE;
            short[] svShort = Utils.createShortArrayFromInt(sv, KyberParams.paramsPolyBytes);  // NO idea what should be the size
            short[] evShort = Utils.createShortArrayFromInt(ev, KyberParams.paramsPolyBytes);
            short[] asv = polyBaseMulMont(aShort, svShort);

            v = polyAdd(asv, evShort);

            // Send H(I), salt, v to the server. //

        } catch (Exception ex) {
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
        return v;
    }

    private static void authenticatedKeyExchange(short[] validator) {

        // p_i is used on both sides. We have decided to separate sides in the following way:
        // piC = p_i on the client's side, piS = p_i on the server's side.

        try {

            // e_1 <- chi // client //

            // chi should be Discrete Gaussian distribution. FIX it
            SecureRandom sr = SecureRandom.getInstanceStrong();
            int e1 = sr.nextInt(2); // Generates 0 or 1 with 50% probability

            // e_1', e_1'' <- chi // server //

            // again chi should be Discrete Gaussian distribution. FIX it
            int e1Prime = sr.nextInt(2); // Generates 0 or 1 with 50% probability
            int e2Prime = sr.nextInt(2); // Generates 0 or 1 with 50% probability

            // KEY -> (s_1, p_i) // client //

            int paramsK = 4;
            KyberPackedPKI keysClient = generateKyberKeys(paramsK);
            byte[] s1 = keysClient.getPackedPrivateKey();
            byte[] piC = keysClient.getPackedPublicKey();

            // KEY -> (s_1', p_j) // server //

            KyberPackedPKI keysServer = generateKyberKeys(paramsK);
            byte[] s1Prime = keysServer.getPackedPrivateKey();
            byte[] pj = keysServer.getPackedPublicKey();

            // p_i' = Compress_q(p_i, d_u) // client //

            int du = 11;
            byte[] piPrime = compressPoly(Utils.byteArrayToShortArray(piC), du);

            // Send i, p_i' to the server. //

            // p_i = Decompress_q(p_i', d_u) // server //

            short[] piS = decompressPoly(piPrime, du);

            // u <- XOF(H(p_i || p_j)) // server //

            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            byte[] intermediateHash = md.digest(Utils.concatByteArrays(Utils.shortArrayToByteArray(piS), pj));
            byte[] u = Utils.nBytesFromShake128(intermediateHash, 2 * KyberParams.paramsPolyBytes);

            // k_j <- (v + p_i) s_1' + uv + e_1'' // server //

            short[] kj = polyBaseMulMont(polyAdd(validator, piS), Utils.byteArrayToShortArray(s1Prime));
            polyBaseMulMont(Utils.byteArrayToShortArray(u), validator);
            kj = polyAdd(kj, polyBaseMulMont(Utils.byteArrayToShortArray(u), validator));

            // sigma_j \in ?_m // server // find out how to generate sigma_j and FIX this

            byte[] sigmaJ = new byte[504];  // NO idea what should be the size
            sr.nextBytes(sigmaJ);

            // v' <- ACon(k_j, sigma_j, params) // server //
            // params = (q, m, g, d, aux) - aux is NOT needed in my opinion

            double q = 12289;
            double m = 16;
            double g = 256;

            int vPrime = Utils.ACon(Utils.bytesToDouble(Utils.shortArrayToByteArray(kj)), Utils.bytesToDouble(sigmaJ), q, m, g);
            // am not the happiest with this - FIX it

        } catch (Exception ex) {
        System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
        ex.printStackTrace();
    }
    }
}