public class ServersKnowledge {

    private final byte[] hashedIdentity;
    private final byte[] salt;
    private final byte[] packedValidator;
    private byte[] sharedSecret;
    private byte[] pi;
    private byte[] pj;

    public ServersKnowledge(byte[] hashedIdentity, byte[] salt, byte[] packedValidator) {
        this.hashedIdentity = hashedIdentity;
        this.salt = salt;
        this.packedValidator = packedValidator;
    }

    public byte[] getHashedIdentity() {
        return hashedIdentity;
    }

    public byte[] getSalt() { return salt; }

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
