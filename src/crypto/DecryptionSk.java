package crypto;

import initiator.Initiator;
import util.CombineData;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class DecryptionSk {

    public static CombineData Decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, ClassNotFoundException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedbytes = cipher.doFinal(data);

        ByteArrayInputStream innputStream = new ByteArrayInputStream(encryptedbytes);
        ObjectInputStream objectInputStream = new ObjectInputStream(innputStream);

        CombineData decryptedData = (CombineData) objectInputStream.readObject();

        return decryptedData;
    }
}
