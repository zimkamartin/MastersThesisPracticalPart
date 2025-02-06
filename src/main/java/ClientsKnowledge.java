public class ClientsKnowledge {

    private final short[] validator;
    private final short[] seed;

    public ClientsKnowledge(short[] seed, short[] validator) {
        this.validator = validator;
        this.seed = seed;
    }

    public short[] getValidator() {
        return validator;
    }

    public short[] getSeed() {
        return seed;
    }
}
