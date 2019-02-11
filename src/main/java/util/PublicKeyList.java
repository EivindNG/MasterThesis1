package util;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.HashMap;

public class PublicKeyList {

    static HashMap<BigInteger, PublicKey> KeyList = new HashMap<BigInteger, PublicKey>();

    public static HashMap<BigInteger, PublicKey> getKeyList() {
        return KeyList;
    }
}
