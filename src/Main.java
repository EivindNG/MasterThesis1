import initiator.Initiator;
import responder.Responder;
import server.KeyPairGenerationBKEM;
import server.Server;
import util.IdMaker;
import util.PublicKeyList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;

import static util.sidGenerator.GenerateSid;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException, IllegalBlockSizeException, ClassNotFoundException, BadPaddingException, NoSuchPaddingException {
        Responder test3 = new Responder();
        Server test2 = new Server();
        Initiator test1 = new Initiator(test2,test3);

        /*

        Responder test3 = new Responder();
        ArrayList<BigInteger> list= new ArrayList<>();
        list.add(BigInteger.valueOf(3));
        list.add(BigInteger.valueOf(4));

        System.out.println(GenerateSid(BigInteger.valueOf(6),BigInteger.valueOf(2),list,BigInteger.valueOf(5)));
        */
    }
}

