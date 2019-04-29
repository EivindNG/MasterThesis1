import FileSharing.InitiatorShare;
import FileSharing.ResponderRetriveFile;
import entities.initiator.Initiator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import entities.responder.Responder;
import entities.server.Server;
import sun.jvm.hotspot.memory.SystemDictionary;
import util.PublicKeyList;
import util.Timestamps;

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

        for (int x = 0; x < 500; x++) {

            Server test2 = new Server();

            ArrayList<Responder> responderList = new ArrayList<Responder>();

            for (int i = 0; i < 1; i++) {

                responderList.add(new Responder());
            }

            Initiator test1 = new Initiator();

            test1.startServer(test2);

            PublicKeyList.getKeyList().clear();
                /*
                PublicKeyList.getKeyList().clear();
                responderList.clear();
            */
        }


        List<String> timelist2 = Timestamps.getTimelist().subList(Timestamps.getTimelist().size()*9/10, Timestamps.getTimelist().size());




        List<Long> timelist1 = new ArrayList<>();


            for (int y = 0; y < timelist2.size()-1; y++) {
                timelist1.add(Long.parseLong(timelist2.get(y + 1).split(", ")[0]) - Long.parseLong(timelist2.get(y).split(", ")[0]));
            }


            List<Long> timelist3 = new ArrayList<>();
            for (int f = 8; f < timelist1.size(); f = f + 9) {
                timelist3.add(timelist1.get(f));
                System.out.println(f);
            }


            double average = 0.0;

            for (long element : timelist3) {
                average = average + element;
            }
            average = average / timelist3.size();

            double std = 0.0;

            for (long element : timelist3) {
                std = std + Math.pow((element - average), 2);
            }
            std = Math.sqrt(std / timelist3.size());

            System.out.println(1 + " " + average + " " + std);
        }


/*
        InitiatorShare shareFile = new InitiatorShare(test1.getIv(),test1.getSharedEncryptionKey(),new File("C:\\Users\\Lenovo\\Documents\\JavaFileSharingTest\\InitiatorSecret.txt"));

        ResponderRetriveFile decyptSharedFile = new ResponderRetriveFile(responderList.get(0).getIv(),responderList.get(0).getSharedEncryptionKey(),new File("C:\\Users\\Lenovo\\Documents\\JavaFileSharingTest\\ResponderDecryptedSharedFile.txt"), new File("C:\\Users\\Lenovo\\Documents\\JavaFileSharingTest\\SharedCloudFile.txt"));
        */
    }


