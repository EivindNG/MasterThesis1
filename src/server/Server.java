package server;


import util.IdMaker;
import util.PublicKeyList;
import util.PublicPrivateKeyGenerator;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class Server {

    private BigInteger id;
    private KeyPair SkPk;

    public Server() throws NoSuchAlgorithmException {
        PublicPrivateKeyGenerator privatepublickey = new PublicPrivateKeyGenerator();
        SkPk = privatepublickey.getPair();
        id = IdMaker.getNextId();
        PublicKeyList.getKeyList().put(id,SkPk.getPublic());


    }
}
