package crypto;

import initiator.Initiator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import util.CombineData;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.*;


public class DecryptionSk {

    public static CombineData Decrypt(EncryptionPk data, PrivateKey privateKey) throws
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException,
            IOException,
            ClassNotFoundException,
            InvalidAlgorithmParameterException, NoSuchProviderException {

        /*
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        */


        IESCipher c1 = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIES();

        Cipher cipher = Cipher.getInstance("ECIES","BC");

        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] aesKeyBytes = cipher.doFinal(data.getCiphertextKey());

        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");

        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        IvParameterSpec iv = new IvParameterSpec("encryptionIntVec".getBytes("UTF-8")); /*Finne paa en annen maate aa  lage IV*/

        decryptCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
        byte[] combinedDecryptedData = decryptCipher.doFinal(data.getCiphertext());

        ByteArrayInputStream innputStream = new ByteArrayInputStream(combinedDecryptedData);
        ObjectInputStream objectInputStream = new ObjectInputStream(innputStream);

        CombineData decryptedData = (CombineData) objectInputStream.readObject();

        return decryptedData;
    }
}
