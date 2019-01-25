package crypto;

import util.CombineData;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;

public class EncryptionPk {
       private byte [] ciphertext;

    public byte[] getCiphertextKey() {
        return ciphertextKey;
    }

    private byte[] ciphertextKey;

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public EncryptionPk(PublicKey pubkey, BigInteger C, BigInteger KEK, String tau, String sid) throws
            IOException,
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException {


        CombineData data = new CombineData(C,KEK,tau,sid);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        ObjectOutputStream objectStream = new ObjectOutputStream(outputStream);
        objectStream.writeObject(data);

        byte dataToBeEncrypted[] = outputStream.toByteArray();


        // Generate key
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(256);
        SecretKey aesKey = kgen.generateKey();

        // Encrypt cipher
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        this.ciphertext = encryptCipher.doFinal(dataToBeEncrypted);



        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, pubkey);
        this.ciphertextKey = cipher.doFinal(aesKey.getEncoded());
    }
}
