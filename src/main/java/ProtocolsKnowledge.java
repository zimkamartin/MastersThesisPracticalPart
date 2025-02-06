public class ProtocolsKnowledge {
    private final ClientsKnowledge clientsKnowledge;
    private final ServersKnowledge serversKnowledge;

    public ProtocolsKnowledge(ClientsKnowledge clientsKnowledge, ServersKnowledge serversKnowledge) {
        this.clientsKnowledge = clientsKnowledge;
        this.serversKnowledge = serversKnowledge;
    }

    public ClientsKnowledge getClientsKnowledge() {
        return clientsKnowledge;
    }

    public ServersKnowledge getServersKnowledge() {
        return serversKnowledge;
    }
}
