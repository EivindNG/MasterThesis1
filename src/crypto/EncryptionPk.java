package crypto;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.Key;
import java.security.PublicKey;
import java.util.ArrayList;

public class EncryptionPk {

    public EncryptionPk(PublicKey pubkey, BigInteger C, BigInteger KEK, BigInteger tau, String sid, ArrayList<BigInteger> pid){
        cipher.init(Cipher.ENCRYPT_MODE, pubkey);
        chiper.doFinal(Byte [] input)

    }
}
