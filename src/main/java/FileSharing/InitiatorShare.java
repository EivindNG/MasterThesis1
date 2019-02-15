package FileSharing;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class InitiatorShare {

    public InitiatorShare(IvParameterSpec iv, Key encryptionKey, File file) throws
            IOException,
            BadPaddingException,
            IllegalBlockSizeException,
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            InvalidAlgorithmParameterException {

        byte[] fileTextInBytes = Files.readAllBytes(file.toPath());

        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        encryptCipher.init(Cipher.ENCRYPT_MODE, encryptionKey,iv);
        byte[] ciphertextFile = encryptCipher.doFinal(fileTextInBytes);

        File SharedCloudFile = new File("C:\\Users\\Lenovo\\Documents\\JavaFileSharingTest\\SharedCloudFile.txt");

        try (FileOutputStream fos = new FileOutputStream(SharedCloudFile)) {
            fos.write(ciphertextFile);
        }
    }
}
