import initiator.Initiator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import responder.Responder;
import server.Server;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) throws
            NoSuchAlgorithmException,
            IOException,
            SignatureException,
            InvalidKeyException,
            IllegalBlockSizeException,
            ClassNotFoundException,
            BadPaddingException,
            NoSuchPaddingException,
            InvalidAlgorithmParameterException,
            NoSuchProviderException {

        Security.addProvider(new BouncyCastleProvider());

        Server test2 = new Server();
        Responder test3 = new Responder(test2);
        ArrayList<Responder> responderList= new ArrayList<Responder>();

        for(int i=0; i < 2; i++){

            Responder test= new Responder(test2);
            responderList.add(test);
        }
        System.out.println(responderList);

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

