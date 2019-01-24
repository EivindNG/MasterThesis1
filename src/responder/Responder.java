package responder;

import crypto.DecryptionSk;
import initiator.Initiator;
import util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class Responder {

    private BigInteger id;
    private KeyPair SkPk;
    private CombineData decryptedData;

    public Responder() throws NoSuchAlgorithmException {
        PublicPrivateKeyGenerator privatepublickey = new PublicPrivateKeyGenerator();
        SkPk = privatepublickey.getPair();
        id = IdMaker.getNextId();
        PublicKeyList.getKeyList().put(id,SkPk.getPublic());

    }

    public void DecryptData(byte[] encryptedData, byte[] sign, BigInteger initiatorID) throws NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            IllegalBlockSizeException,
            ClassNotFoundException,
            BadPaddingException,
            NoSuchPaddingException,
            IOException {
        if (SignVerifyer.Verify(sign,PublicKeyList.getKeyList().get(initiatorID),encryptedData)){
            decryptedData = DecryptionSk.Decrypt(encryptedData,SkPk.getPrivate());
            System.out.println("Great success, STAGE 2");
        }
    }
}

