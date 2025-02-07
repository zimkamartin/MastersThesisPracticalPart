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

        ProtocolsKnowledge protocol = establishValidator();
        authenticatedKeyExchange(protocol);
        mutualVerification(protocol);

        System.out.print("Everything went well...");

    }

    private static ProtocolsKnowledge establishValidator() {

        // Everything is on the client's side.

        short[] validator = new short[64];  // NO idea what should be the size
        short[] seed = new short[KyberParams.paramsPolyBytes];
        int sv = 0;

        byte[] hashedIdentity = new byte[0];
        byte[] salt = new byte[0];

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

            seed = uniformRandom.getUniformR();  // length = 384 because of KyberParams.paramsPolyBytes

            // a = SHAKE-128(seed) //

            byte[] a = Utils.nBytesFromShake128(Utils.shortArrayToByteArray(seed), 2 * KyberParams.paramsPolyBytes);

            // seed1 = H(salt || H(I || pwd)) //

            String i = "identity123";
            String pwd = "password123";
            String iPwdConcatenated = i.concat(pwd);

            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            md.reset();
            byte[] intermediateHashSeed = md.digest(iPwdConcatenated.getBytes());

            // Create random input of bytes for generateUniform
            salt = new byte[64];  // NO idea what should be the size
            sr.nextBytes(salt);

            md.reset();
            byte[] seed1 = md.digest(Utils.concatByteArrays(salt, intermediateHashSeed));

            // seed2 = H(seed1) //

            md.reset();
            byte[] seed2 = md.digest(seed1);

            // s_v <- PRNG(seed1) // WHAT should be PRNG? If Discrete Gaussian distribution, then how to use it?
            // also because of the computation of v, s_v should be \in R_q and use polyBaseMulMont

            sv = sr.nextInt(Short.MAX_VALUE);  // FIX it

            // e_v <- PRNG(seed1) // WHAT should be PRNG? If Discrete Gaussian distribution, then how to use it?
            // also because of the computation of v, e_v should be \in R_q and use polyBaseMulMont

            int ev = sr.nextInt(Short.MAX_VALUE);  // FIX it

            // v <- as_v + e_v \in R_q //

            short[] aShort = Utils.byteArrayToShortArray(a);
            short[] svShort = Utils.createShortArrayFromInt(sv, KyberParams.paramsPolyBytes);  // NO idea what should be the size
            short[] evShort = Utils.createShortArrayFromInt(ev, KyberParams.paramsPolyBytes);
            short[] asv = polyBaseMulMont(aShort, svShort);

            validator = polyAdd(asv, evShort);

            // Send H(I), salt, v to the server. //
            md.reset();
            hashedIdentity = md.digest(i.getBytes());

        } catch (Exception ex) {
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }

        return new ProtocolsKnowledge(new ClientsKnowledge(seed, sv, validator), new ServersKnowledge(hashedIdentity, salt, validator));
    }

    private static void authenticatedKeyExchange(ProtocolsKnowledge protocol) {

        // Variables p_{i,j}, u are used on both sides. We have decided to separate sides in the following way:
        // p{i,j}C = p_{i,j} on the client's side, p{i,j}S = p_{i,j} on the server's side.
        // uC = u on the client's side, uS = u on the server's side.

        int svC = protocol.getClientsKnowledge().getSv();
        short[] vC = protocol.getClientsKnowledge().getValidator();

        short[] vS = protocol.getServersKnowledge().getValidator();

        try {

            // e_1 <- chi // client // WHY do we need it?

            // chi should be Discrete Gaussian distribution. FIX it
            SecureRandom sr = SecureRandom.getInstanceStrong();
            int e1 = sr.nextInt(2); // Generates 0 or 1 with 50% probability

            // e_1', e_1'' <- chi // server // WHY do we need e_1'?

            // again chi should be Discrete Gaussian distribution. FIX it
            int e1Prime = sr.nextInt(2); // Generates 0 or 1 with 50% probability
            int e1DoublePrime = sr.nextInt(2); // Generates 0 or 1 with 50% probability

            // KEY -> (s_1, p_i) // client //

            int paramsK = 4;
            KyberPackedPKI keysClient = generateKyberKeys(paramsK);
            byte[] s1 = keysClient.getPackedPrivateKey();
            byte[] piC = keysClient.getPackedPublicKey();

            // KEY -> (s_1', p_j) // server //

            KyberPackedPKI keysServer = generateKyberKeys(paramsK);
            byte[] s1Prime = keysServer.getPackedPrivateKey();
            byte[] pjS = keysServer.getPackedPublicKey();

            // p_i' = Compress_q(p_i, d_u) // client //

            int du = 11;
            byte[] piPrime = compressPoly(Utils.byteArrayToShortArray(piC), du);

            // Send i, p_i' to the server. //

            // p_i = Decompress_q(p_i', d_u) // server //

            short[] piS = decompressPoly(piPrime, du);

            // u <- XOF(H(p_i || p_j)) // server //

            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            md.reset();
            byte[] intermediateHashUServer = md.digest(Utils.concatByteArrays(Utils.shortArrayToByteArray(piS), pjS));
            byte[] uS = Utils.nBytesFromShake128(intermediateHashUServer, 2 * KyberParams.paramsPolyBytes);

            // k_j <- (v + p_i) s_1' + uv + e_1'' // server //

            short[] kj = polyBaseMulMont(polyAdd(vS, piS), Utils.byteArrayToShortArray(s1Prime));
            polyBaseMulMont(Utils.byteArrayToShortArray(uS), vS);
            kj = polyAdd(kj, polyBaseMulMont(Utils.byteArrayToShortArray(uS), vS));
            kj = polyAdd(kj, Utils.createShortArrayFromInt(e1DoublePrime, 2 * KyberParams.paramsPolyBytes));

            // sigma_j \in ?_m // server // find out how to generate sigma_j and FIX this

            byte[] sigmaj = new byte[504];  // NO idea what should be the size
            sr.nextBytes(sigmaj);

            // v' <- ACon(k_j, sigma_j, params) // server //
            // params = (q, m, g, d, aux) - aux is NOT needed in my opinion

            double q = 12289;
            double m = 16;
            double g = 256;

            int vPrime = Utils.ACon(Utils.bytesToDouble(Utils.shortArrayToByteArray(kj)), Utils.bytesToDouble(sigmaj), q, m, g);
            // am not the happiest with this - FIX it

            // p_j' = Compress_q(p_j, d_v) // server //
            int dv = 3;
            byte[] pjPrime = compressPoly(Utils.byteArrayToShortArray(pjS), dv);

            // Send salt, p_j', v', H(salt, p_j', v') to the client. //

            // p_j = Decompress_q(p_j', d_v) // client //

            short[] pjC = decompressPoly(pjPrime, dv);

            // u <- XOF(H(p_i || p_j)) // client //

            md.reset();
            byte[] intermediateHashUClient = md.digest(Utils.concatByteArrays(piC, Utils.shortArrayToByteArray(pjC)));
            byte[] uC = Utils.nBytesFromShake128(intermediateHashUClient, 2 * KyberParams.paramsPolyBytes);

            // v <- as_v + e_v \in R_q // client // that is vC

            // k_i <- (p_j - v) * (s_v + s_1 ) + uv

            short[] fstBracket = polySub(pjC, vC);
            short[] sndBracket = polyAdd(Utils.createShortArrayFromInt(svC, 2 * KyberParams.paramsPolyBytes), Utils.byteArrayToShortArray(s1));

            short[] ki = polyAdd(polyBaseMulMont(fstBracket, sndBracket), polyBaseMulMont(Utils.byteArrayToShortArray(uC), vC));

            // sigma_i <- ARec(k_i, v', params) // client //
            // params = (q, m, g, d, aux) - aux is NOT needed in my opinion

            int sigmai = Utils.ARec(Utils.bytesToDouble(Utils.shortArrayToByteArray(ki)), vPrime, q, m, g);

            // sk_i <- SHA3-256(sigma_i) // client //

            md.reset();
            byte[] ski = md.digest(Utils.intToByteArray(sigmai));

            // sk_j <- SHA3-256(sigma_j) // server //

            md.reset();
            byte[] skj = md.digest(sigmaj);

            // Save shared secrets //

            protocol.getClientsKnowledge().setSharedSecret(ski);
            protocol.getServersKnowledge().setSharedSecret(skj);

            // Save p_i and p_js //

            protocol.getClientsKnowledge().setPi(piC);
            protocol.getClientsKnowledge().setPj(pjC);
            protocol.getServersKnowledge().setPi(piS);
            protocol.getServersKnowledge().setPj(pjS);

        } catch (Exception ex) {
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
    }

    private static void mutualVerification(ProtocolsKnowledge protocol) {

        byte[] piC = protocol.getClientsKnowledge().getPi();
        short[] pjC = protocol.getClientsKnowledge().getPj();
        byte[] ski = protocol.getClientsKnowledge().getSharedSecret();

        short[] piS = protocol.getServersKnowledge().getPi();
        byte[] pjS = protocol.getServersKnowledge().getPj();
        byte[] skj = protocol.getServersKnowledge().getSharedSecret();

        try {

            // M_1 = SHA3-256(p_i || p_j || sk_i ) // client //

            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            md.reset();
            byte[] m1 = md.digest(Utils.concatByteArrays(Utils.concatByteArrays(piC, Utils.shortArrayToByteArray(pjC)), ski));

            // Send M_1 to the server. //

            // M_2 = SHA3-256(p_i || p_j || sk_j ) // server //

            md.reset();
            byte[] m2 = md.digest(Utils.concatByteArrays(Utils.concatByteArrays(Utils.shortArrayToByteArray(piS), pjS), skj));

            // Verify M_2 = M_1 // server //

            System.out.println(Arrays.equals(m1, m2));

            // M_3 = SHA3-256(p_i || M_2 || sk_j ) // server //

            md.reset();
            byte[] m3 = md.digest(Utils.concatByteArrays(Utils.concatByteArrays(Utils.shortArrayToByteArray(piS), m2), skj));

            // Send M_3 to the client. //

            // M_4 = SHA3-256(p_i || M_1 || sk_i ) // server //

            md.reset();
            byte[] m4 = md.digest(Utils.concatByteArrays(Utils.concatByteArrays(piC, m1), ski));

            // Verify M_4 = M_3 // client //

            System.out.println(Arrays.equals(m4, m3));

        } catch (Exception ex) {
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
    }
}