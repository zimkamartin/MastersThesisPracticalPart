public class ClientsKnowledge {

    private final String identity;
    private final String password;
    private final short[] seed;
    private final byte[] packedValidator;
    private byte[] sharedSecret;
    private byte[] pi;
    private byte[] pj;

    public ClientsKnowledge(String identity, String password, short[] seed, byte[] packedValidator) {
        this.identity = identity;
        this.password = password;
        this.seed = seed;
        this.packedValidator = packedValidator;
    }

    public String getIdentity() { return identity; }

    public short[] getSeed() {
        return seed;
    }

    public byte[] getPackedValidator() {
        return packedValidator;
    }

    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public void setPi(byte[] pi) {
        this.pi = pi;
    }

    public byte[] getPi() {
        return pi;
    }

    public void setPj(byte[] pj) {
        this.pj = pj;
    }

    public byte[] getPj() {
        return pj;
    }
}
