package FileSharing;

import entities.responder.Responder;

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
import java.security.NoSuchAlgorithmException;

public class ResponderRetriveFile {

    public ResponderRetriveFile(IvParameterSpec iv, SecretKeySpec encryptionKey, File responderFile, File cloudFile) throws
            IOException,
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException,
            InvalidAlgorithmParameterException {

        byte[] fileTextInBytes = Files.readAllBytes(cloudFile.toPath());

        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        decryptCipher.init(Cipher.DECRYPT_MODE, encryptionKey,iv);
        byte[] DecryptedFileData = decryptCipher.doFinal(fileTextInBytes);

        try (FileOutputStream fos = new FileOutputStream(responderFile)) {
            fos.write(DecryptedFileData);
        }
    }
}
