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
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

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

        /*
        List<Long> timelist= new ArrayList();
        for(int a = 1; a < 10001; a=a*10) {
            for (int x = 0; x < 300; x++) {

                long time = System.nanoTime();
*/
        Server test2 = new Server();

        ArrayList<Responder> responderList = new ArrayList<Responder>();

        for (int i = 0; i < 2; i++) {
            System.out.println("test");
            responderList.add(new Responder());
        }

        Initiator test1 = new Initiator();

        test1.startServer();
/*
                long time2 = System.nanoTime();

                timelist.add(time2 - time);

            }

            timelist = timelist.subList(250, timelist.size());
            double average = 0.0;

            for (long element : timelist) {
                average = average + element;
            }
            average = average / timelist.size();

            double std = 0.0;

            for (long element : timelist) {
                std = std + Math.pow((element - average), 2);
            }
            std = Math.sqrt(std / timelist.size());

            System.out.println(a + " " + average + " " + std);
            timelist.clear();
        }
/*
        test1.startServer();

        InitiatorShare shareFile = new InitiatorShare(test1.getIv(),test1.getSharedEncryptionKey(),new File("C:\\Users\\Lenovo\\Documents\\JavaFileSharingTest\\InitiatorSecret.txt"));

        ResponderRetriveFile decyptSharedFile = new ResponderRetriveFile(responderList.get(0).getIv(),responderList.get(0).getSharedEncryptionKey(),new File("C:\\Users\\Lenovo\\Documents\\JavaFileSharingTest\\ResponderDecryptedSharedFile.txt"), new File("C:\\Users\\Lenovo\\Documents\\JavaFileSharingTest\\SharedCloudFile.txt"));
        */
    }
}

