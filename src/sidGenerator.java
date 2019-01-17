import initiator.Initiator;
import responder.Responder;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class sidGenerator {


    private Initiator I;
    private BigInteger Nonce;
    private ArrayList<Responder> pid;
    private BigInteger KeyEncryptionKey;
    private String concatValues;
    private String sid;

    public sidGenerator(Initiator I, BigInteger Nonce, ArrayList<Responder> pid, BigInteger KeyEncryptionKey) throws NoSuchAlgorithmException {
        this.I = I;
        this.Nonce = Nonce;
        this.pid = pid;
        this.KeyEncryptionKey = KeyEncryptionKey;

        /*
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageDigest = md.digest(input.getBytes());
        BigInteger no = new BigInteger(1, messageDigest);
        String hashtext = no.toString(16);

        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        sid = hashtext;
        */
    }
}
