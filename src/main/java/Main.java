import FileSharing.InitiatorShare;
import FileSharing.ResponderRetriveFile;
import entities.initiator.Initiator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import entities.responder.Responder;
import entities.server.Server;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;

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
            NoSuchProviderException, InvalidKeySpecException {

        Security.addProvider(new BouncyCastleProvider());

        /*ArrayList<Long> timelist= new ArrayList();

        for(int x=0; x <99; x++) {
            Date date = new Date();
            long time = date.getTime();
            System.out.println("Time in Milliseconds: " + time);
*/
            Server test2 = new Server();

            ArrayList<Responder> responderList = new ArrayList<Responder>();

            for (int i = 0; i < 2; i++) {

                responderList.add(new Responder());
            }

            Initiator test1 = new Initiator();
            /*
            Date date2 = new Date();
            long time2 = date2.getTime();
            System.out.println("Time in Milliseconds: " + time2);
            timelist.add(time2-time);

        }
        System.out.println(timelist);
        */

        test1.startServer();
        /*
        InitiatorShare shareFile = new InitiatorShare(test1.getIv(),test1.getSharedEncryptionKey(),new File("C:\\Users\\Lenovo\\Documents\\JavaFileSharingTest\\InitiatorSecret.txt"));

        ResponderRetriveFile decyptSharedFile = new ResponderRetriveFile(responderList.get(0).getIv(),responderList.get(0).getSharedEncryptionKey(),new File("C:\\Users\\Lenovo\\Documents\\JavaFileSharingTest\\ResponderDecryptedSharedFile.txt"), new File("C:\\Users\\Lenovo\\Documents\\JavaFileSharingTest\\SharedCloudFile.txt"));
        */
    }
}

