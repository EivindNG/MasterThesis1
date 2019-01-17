import initiator.Initiator;
import server.KeyPairGenerationBKEM;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Initiator test = new Initiator();
        System.out.println(test);


        /*KeyPairGenerationBKEM key = new KeyPairGenerationBKEM(BigInteger.valueOf(7));
        System.out.println(key);
        */
        /*initiator.Initiator noe = new initiator.Initiator();
        try {
            noe.initiator();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }*/
    }
}
