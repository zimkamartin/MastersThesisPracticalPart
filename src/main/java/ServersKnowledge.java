public class ServersKnowledge {

    private final byte[] hashedIdentity;
    private final byte[] salt;
    private final short[] validator;
    private byte[] sharedSecret;

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
}
