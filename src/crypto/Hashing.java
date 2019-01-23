package crypto;

import java.math.BigInteger;
import java.security.MessageDigest;

public class Hashing {

    public static String hash(byte[] data, byte[] messageDigest){

        BigInteger no = new BigInteger(1, messageDigest);
        String hashtext = no.toString(16);

        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }
        return hashtext;
    }
}
