package crypto;

import initiator.Initiator;
import util.CombineData;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class DecryptionSk {

    public static CombineData Decrypt(EncryptionPk data, PrivateKey privateKey) throws
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException,
            IOException,
            ClassNotFoundException,
            InvalidAlgorithmParameterException {


        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] aesKeyBytes = cipher.doFinal(data.getCiphertextKey());
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");


        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(aesKey.getEncoded());
        decryptCipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
        byte[] combinedDecryptedData = decryptCipher.doFinal(data.getCiphertext());

        ByteArrayInputStream innputStream = new ByteArrayInputStream(combinedDecryptedData);
        ObjectInputStream objectInputStream = new ObjectInputStream(innputStream);

        CombineData decryptedData = (CombineData) objectInputStream.readObject();

        return decryptedData;
    }
}
