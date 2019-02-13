package crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static java.security.MessageDigest.getInstance;

public class KeyDerivation {

    public static byte[] KDF(BigInteger tall, BigInteger k, byte[] sid) throws
            NoSuchAlgorithmException,
            IOException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(tall.toByteArray());
        outputStream.write(k.toByteArray());
        outputStream.write(sid);

        byte AltSammen[] = outputStream.toByteArray( );

        MessageDigest md = getInstance("SHA-256");
        byte[] messageDigest = md.digest(AltSammen);

        return messageDigest;
    }
}
