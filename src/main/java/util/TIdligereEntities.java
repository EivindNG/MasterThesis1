package util;

import entities.initiator.Initiator;
import entities.responder.Responder;
import entities.server.Server;

import java.math.BigInteger;

public class TIdligereEntities {
    Responder responder=null;
    Server server=null;
    Initiator initiator=null;
    BigInteger id;
    Class kalsse;

    public Responder getResponder() {
        return responder;
    }

    public Class getclass(){return kalsse;}

    public Server getServer() {
        return server;
    }

    public Initiator getInitiator() {
        return initiator;
    }

    public BigInteger getId() {
        return id;
    }

    public TIdligereEntities(Object object, BigInteger id) {

        if(object.getClass().equals(Responder.class)){
            this.responder = (Responder) object;
            this.id = id;
            this.kalsse = responder.getClass();
        }

        if(object.getClass().equals(Initiator.class)){
            this.initiator = (Initiator) object;
            this.id = id;
            this.kalsse = initiator.getClass();
        }
        if(object.getClass().equals(Server.class)){
            this.server = (Server) object;
            this.id = id;
            this.kalsse = server.getClass();
        }

    }
}
