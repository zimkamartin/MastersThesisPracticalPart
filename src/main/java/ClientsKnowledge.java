public class ClientsKnowledge {

    private final short[] seed;
    private final int sv;
    private final short[] validator;
    private byte[] sharedSecret;
    private byte[] pi;
    private short[] pj;

    public ClientsKnowledge(short[] seed, int sv, short[] validator) {
        this.seed = seed;
        this.sv = sv;
        this.validator = validator;
    }

    public short[] getSeed() {
        return seed;
    }

    public int getSv() {
        return sv;
    }

    public short[] getValidator() {
        return validator;
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

    public void setPj(short[] pj) {
        this.pj = pj;
    }

    public short[] getPj() {
        return pj;
    }
}
