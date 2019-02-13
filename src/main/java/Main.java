import entities.initiator.Initiator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import entities.responder.Responder;
import entities.server.Server;
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

        ArrayList<Responder> responderList= new ArrayList<Responder>();

        for(int i=0; i < 10; i++){

            Responder test= new Responder(test2);
            responderList.add(test);
        }


        Initiator test1 = new Initiator(test2,responderList);

    }
}

