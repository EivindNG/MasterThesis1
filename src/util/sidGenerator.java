package util;

import crypto.hashing;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import static java.security.MessageDigest.*;

public class sidGenerator {

    public static String GenerateSid(BigInteger id, BigInteger Nonce, ArrayList<BigInteger> pid, BigInteger KeyEncryptionKey) throws NoSuchAlgorithmException, IOException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(id.toByteArray());
        outputStream.write(Nonce.toByteArray());
        for(BigInteger ID: pid){
            outputStream.write(ID.toByteArray());
        }
        outputStream.write(KeyEncryptionKey.toByteArray());
        byte AltSammen[] = outputStream.toByteArray( );


        MessageDigest md = getInstance("SHA-256");
        byte[] messageDigest = md.digest(AltSammen);

        String hashtext = hashing.hash(AltSammen,messageDigest);

        return hashtext;

    }
}
