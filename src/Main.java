import initiator.Initiator;
import responder.Responder;
import server.Server;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;

public class Main {

    public static void main(String[] args) throws
            NoSuchAlgorithmException,
            IOException,
            SignatureException,
            InvalidKeyException,
            IllegalBlockSizeException,
            ClassNotFoundException,
            BadPaddingException,
            NoSuchPaddingException, InvalidAlgorithmParameterException {

        Server test2 = new Server();
        Responder test3 = new Responder(test2);
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

