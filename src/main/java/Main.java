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

            String i = "identity123";

            MessageDigest md = MessageDigest.getInstance("SHA3-256");

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

        return new ProtocolsKnowledge(new ClientsKnowledge(seed, sv, validator), new ServersKnowledge(hashedIdentity, validator));
    }

    private static void authenticatedKeyExchange(ProtocolsKnowledge protocol) {

        // Variables p_{i,j}, u are used on both sides. We have decided to separate sides in the following way:
        // p{i,j}C = p_{i,j} on the client's side, p{i,j}S = p_{i,j} on the server's side.
        // uC = u on the client's side, uS = u on the server's side.

        int svC = protocol.getClientsKnowledge().getSv();
        short[] vC = protocol.getClientsKnowledge().getValidator();

        short[] vS = protocol.getServersKnowledge().getValidator();

        try {

            SecureRandom sr = SecureRandom.getInstanceStrong();

            // e_1'' <- chi // server //

            // again chi should be Discrete Gaussian distribution. FIX it
            int e1DoublePrime = sr.nextInt(2); // Generates 0 or 1 with 50% probability

            // KEY -> (s_1, p_i) // client //

            int paramsK = 4;
            KyberPackedPKI keysClient = generateKyberKeys(paramsK);
            byte[] s1 = keysClient.getPackedPrivateKey();
            byte[] pi = keysClient.getPackedPublicKey();

            // KEY -> (s_1', p_j) // server //

            KyberPackedPKI keysServer = generateKyberKeys(paramsK);
            byte[] s1Prime = keysServer.getPackedPrivateKey();
            byte[] pj = keysServer.getPackedPublicKey();

            MessageDigest md = MessageDigest.getInstance("SHA3-256");

            // sigma_j \in ?_m // server // find out how to generate sigma_j and FIX this

            byte[] sigma = new byte[504];  // NO idea what should be the size
            sr.nextBytes(sigma);

            // Send salt, p_j', v', H(salt, p_j', v') to the client. //

            // v <- as_v + e_v \in R_q // client // that is vC

            // sk_i <- SHA3-256(sigma_i) // client //

            md.reset();
            byte[] ski = md.digest(sigma);

            // sk_j <- SHA3-256(sigma_j) // server //

            md.reset();
            byte[] skj = md.digest(sigma);

            // Save shared secrets //

            protocol.getClientsKnowledge().setSharedSecret(ski);
            protocol.getServersKnowledge().setSharedSecret(skj);

            // Save p_i and p_js //

            protocol.getClientsKnowledge().setPi(pi);
            protocol.getClientsKnowledge().setPj(pj);
            protocol.getServersKnowledge().setPi(pi);
            protocol.getServersKnowledge().setPj(pj);

        } catch (Exception ex) {
            System.out.println("generateKyberKeys Exception! [" + ex.getMessage() + "]");
            ex.printStackTrace();
        }
    }

    private static void mutualVerification(ProtocolsKnowledge protocol) {

        byte[] piC = protocol.getClientsKnowledge().getPi();
        byte[] pjC = protocol.getClientsKnowledge().getPj();
        byte[] ski = protocol.getClientsKnowledge().getSharedSecret();

        byte[] piS = protocol.getServersKnowledge().getPi();
        byte[] pjS = protocol.getServersKnowledge().getPj();
        byte[] skj = protocol.getServersKnowledge().getSharedSecret();

        try {

            // M_1 = SHA3-256(p_i || p_j || sk_i ) // client //

            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            md.reset();
            byte[] m1 = md.digest(Utils.concatByteArrays(Utils.concatByteArrays(piC, pjC), ski));

            // Send M_1 to the server. //

            // M_2 = SHA3-256(p_i || p_j || sk_j ) // server //

            md.reset();
            byte[] m2 = md.digest(Utils.concatByteArrays(Utils.concatByteArrays(piS, pjS), skj));

            // Verify M_2 = M_1 // server //

            System.out.println(Arrays.equals(m1, m2));

            // M_3 = SHA3-256(p_i || M_2 || sk_j ) // server //

            md.reset();
            byte[] m3 = md.digest(Utils.concatByteArrays(Utils.concatByteArrays(piS, m2), skj));

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