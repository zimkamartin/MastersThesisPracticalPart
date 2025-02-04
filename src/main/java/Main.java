import com.swiftcryptollc.crypto.provider.KyberJCE;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        System.out.print("Just some print 01.");

        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new KyberJCE());

        // Alice generates a KeyPair and sends her public key to Bob
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber1024");
        System.out.print("Just some print 02.");
    }
}