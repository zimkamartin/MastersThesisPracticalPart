public class ServersKnowledge {

    private final byte[] hashedIdentity;
    private final short[] validator;
    private byte[] sharedSecret;
    private byte[] pi;
    private byte[] pj;

    public ServersKnowledge(byte[] hashedIdentity, short[] validator) {
        this.hashedIdentity = hashedIdentity;
        this.validator = validator;
    }

    public byte[] getHashedIdentity() {
        return hashedIdentity;
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

    public void setPj(byte[] pj) {
        this.pj = pj;
    }

    public byte[] getPj() {
        return pj;
    }
}
