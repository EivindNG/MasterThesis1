import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;

public class signing {

    private KeyPair pair;
    private byte[] signature;

    public signing(KeyPair pair, ArrayList<BigInteger Stufftosign>) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        Signature sign = Signature.getInstance("SHA256withDSA");
        sign.initSign(pair.getPrivate());

        byte[] bytes = "Hello how are you".getBytes(); /*Alt om til bytes? */

        sign.update(bytes);

        byte[] signature = sign.sign();
    }
}
