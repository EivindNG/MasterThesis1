package util;

import java.math.BigInteger;
import java.security.Key;
import java.util.HashMap;

public class PublicKeyList {

    static HashMap<BigInteger,Key> KeyList = new HashMap<BigInteger, Key>();

    public static HashMap<BigInteger, Key> getKeyList() {
        return KeyList;
    }
}
