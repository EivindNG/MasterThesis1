package crypto;

import entities.AbstractEntitiy;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import util.AESandIV;
import util.CombineData;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;


public class EncryptionPk {
    private byte[] ciphertext;
    private byte[] ciphertextKey;


    public byte[] getCiphertextKey() {
        return ciphertextKey;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public EncryptionPk(PublicKey pubkey, ECPoint C, ECPoint KEK, byte[] tau, byte[] sid, ArrayList pidIDs) throws
            IOException,
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchProviderException {




        CombineData data = new CombineData(C,KEK,tau,sid,pidIDs);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectStream = new ObjectOutputStream(outputStream);
        objectStream.writeObject(data);

        byte dataToBeEncrypted[] = outputStream.toByteArray();


        // Generate key
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey aesKey = kgen.generateKey();

        byte [] ivBytes = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(ivBytes);

        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // Encrypt cipher
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey,iv);
        this.ciphertext = encryptCipher.doFinal(dataToBeEncrypted);
        /*
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        */
        IESCipher c1 = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIES();

        Cipher cipher = Cipher.getInstance("ECIES","BC");

        AESandIV aesAndiv = new AESandIV(iv,aesKey);

        ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
        ObjectOutputStream objectStream2 = new ObjectOutputStream(outputStream2);
        objectStream2.writeObject(aesAndiv);

        byte AESandIVtoBeEncrypted[] = outputStream2.toByteArray();

        cipher.init(Cipher.ENCRYPT_MODE, pubkey);
        this.ciphertextKey = cipher.doFinal(AESandIVtoBeEncrypted);
    }
}
