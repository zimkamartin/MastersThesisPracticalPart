public class ServersKnowledge {
    // Send H(I), salt, v to the server

    private final byte[] hashedIdentity;
    private final byte[] salt;
    private final short[] validator;

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
}
