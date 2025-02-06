public class ClientsKnowledge {

    private final short[] seed;
    private final int sv;
    private final short[] validator;

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
}
