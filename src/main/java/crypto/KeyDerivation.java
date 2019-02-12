package crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static java.security.MessageDigest.getInstance;

public class KeyDerivation {

    public static String KDF(BigInteger tall, BigInteger k, String sid) throws
            NoSuchAlgorithmException,
            IOException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(tall.toByteArray());
        outputStream.write(k.toByteArray());
        outputStream.write(sid.getBytes());

        byte AltSammen[] = outputStream.toByteArray( );

        MessageDigest md = getInstance("SHA-256");
        byte[] messageDigest = md.digest(AltSammen);

        String hashtext = Hashing.hash(AltSammen,messageDigest);

        return hashtext;
    }
}
