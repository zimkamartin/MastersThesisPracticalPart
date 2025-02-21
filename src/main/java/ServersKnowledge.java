public class ServersKnowledge {

    private final byte[] hashedIdentity;
    private final byte[] salt;
    private final short[] validator;
    private byte[] sharedSecret;
    private short[] pi;
    private byte[] pj;

    public ServersKnowledge(byte[] hashedIdentity, byte[] salt, short[] validator) {
        this.hashedIdentity = hashedIdentity;
        this.salt = salt;
        this.validator = validator;
    }

    public byte[] getHashedIdentity() {
        return hashedIdentity;
    }

    public byte[] getSalt() {
        return salt;
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

    public void setPi(short[] pi) {
        this.pi = pi;
    }

    public short[] getPi() {
        return pi;
    }

    public void setPj(byte[] pj) {
        this.pj = pj;
    }

    public byte[] getPj() {
        return pj;
    }
}
