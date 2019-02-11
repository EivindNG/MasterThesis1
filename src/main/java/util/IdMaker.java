package util;

import java.math.BigInteger;

public class IdMaker {
    static BigInteger id = BigInteger.valueOf(0);

    static public BigInteger getNextId(){
        id = id.add(BigInteger.valueOf(1));
        return id;
    }
}
