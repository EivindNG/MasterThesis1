package util;

import entities.AbstractEntitiy;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.HashMap;

public class PublicKeyList {

    static HashMap<AbstractEntitiy, PublicKey> KeyList = new HashMap<>();

    public static HashMap<AbstractEntitiy, PublicKey> getKeyList() {
        return KeyList;
    }
}
