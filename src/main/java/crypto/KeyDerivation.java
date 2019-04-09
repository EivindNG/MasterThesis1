package crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class KeyDerivation {

    public static byte[] KDF(BigInteger tall, BigInteger k, byte[] sid) throws
            NoSuchAlgorithmException,
            IOException, InvalidKeySpecException, NoSuchProviderException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(tall.toByteArray());
        outputStream.write(k.toByteArray());
        outputStream.write(sid);

        byte AltSammen[] = outputStream.toByteArray( );
        /*
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageDigest = md.digest(AltSammen);

        return messageDigest;
        */
        /*
        GeneralDigest algorithm = new SHA256Digest();
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(algorithm);
        gen.init(AltSammen, AltSammen, 2);
        byte[] dk = ((KeyParameter) gen.generateDerivedParameters(272*8)).getKey();
        */



        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(AltSammen,null,null));

        byte[] okm = new byte[48];
        hkdf.generateBytes(okm, 0, 48);

        return okm;


        /*
        SHA256Digest md = new SHA256Digest();
        md.update(AltSammen,0,AltSammen.length);

        byte[] messageDigest = md.digest(AltSammen);


        KDF1BytesGenerator keyandiv = new KDF1BytesGenerator(md);

        byte[] messageDigest = new byte[272];
        keyandiv.generateBytes(messageDigest,0,272);
           */
    }
}
