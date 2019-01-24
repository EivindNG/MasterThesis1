package crypto;

import util.CombineData;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;

public class EncryptionPk {


    public static byte[] Encrypt(PublicKey pubkey, BigInteger C, BigInteger KEK, String tau, String sid) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        CombineData data = new CombineData(C,KEK,tau,sid);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        ObjectOutputStream objectStream = new ObjectOutputStream(outputStream);
        objectStream.writeObject(data);


        byte dataToBeEncrypted[] = outputStream.toByteArray();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, pubkey);
        byte[] ciphertext = cipher.doFinal(dataToBeEncrypted);

        return ciphertext;
    }
}
