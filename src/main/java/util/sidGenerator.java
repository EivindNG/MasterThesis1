package util;

import entities.AbstractEntitiy;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HashMap;

import static java.security.MessageDigest.*;

public class sidGenerator {

    public static byte[] GenerateSid(BigInteger id, BigInteger Nonce, HashMap<AbstractEntitiy, PublicKey> pid, ECPoint KeyEncryptionKey) throws
            NoSuchAlgorithmException,
            IOException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(id.toByteArray());
        outputStream.write(Nonce.toByteArray());
        for (AbstractEntitiy entity : pid.keySet()) {
            outputStream.write(entity.getId().toByteArray());
        }
        outputStream.write(KeyEncryptionKey.getEncoded(false));

        byte AltSammen[] = outputStream.toByteArray( );


        MessageDigest md = getInstance("SHA-256");
        byte[] messageDigest = md.digest(AltSammen);

        return messageDigest;

    }
}
