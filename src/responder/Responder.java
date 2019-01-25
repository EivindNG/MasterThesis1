package responder;

import crypto.DecryptionSk;
import crypto.EncryptionPk;
import crypto.KeyDerivation;
import server.Server;
import util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;

public class Responder {

    private BigInteger id;
    private KeyPair SkPk;
    private CombineData decryptedData;
    private Blind blind;
    private Server server;
    private String SharedEncryptionKey;

    public Responder(Server server) throws
            NoSuchAlgorithmException {
        this.server = server;
        PublicPrivateKeyGenerator privatepublickey = new PublicPrivateKeyGenerator();
        SkPk = privatepublickey.getPair();
        id = IdMaker.getNextId();
        PublicKeyList.getKeyList().put(id,SkPk.getPublic());

    }

    public void DecryptData(EncryptionPk encryptedData, byte[] sign, BigInteger initiatorID) throws
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            IllegalBlockSizeException,
            ClassNotFoundException,
            BadPaddingException,
            NoSuchPaddingException,
            IOException,
            InvalidAlgorithmParameterException {

        if (SignVerifyer.Verify(sign,PublicKeyList.getKeyList().get(initiatorID),encryptedData.getCiphertext())){
            decryptedData = DecryptionSk.Decrypt(encryptedData,SkPk.getPrivate());

            System.out.println("Great success, STAGE 2");

            BlindAndSign(decryptedData.getC(),decryptedData.getSid(),decryptedData.getKEK());
        }
    }

    public BigInteger getId() {
        return id;
    }

    public void BlindAndSign(BigInteger C, String sid, BigInteger ek) throws NoSuchAlgorithmException,
            IOException,
            SignatureException,
            InvalidKeyException {

        blind = new Blind(C);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(sid.getBytes());
        outputStream.write(ek.toByteArray());
        outputStream.write(blind.getBlindC().toByteArray());

        server.Decapsulate(sid, blind.getBlindC(), Signing.Sign(SkPk,outputStream.toByteArray()),this);
    }

    public void UnblindAndKDF(String sid, BigInteger blindk, byte[] sign, Server server) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
        outputStream2.write(sid.getBytes());
        outputStream2.write(blindk.toByteArray());

        if (SignVerifyer.Verify(sign, PublicKeyList.getKeyList().get(server.getId()),outputStream2.toByteArray())){

            BigInteger k = Unblinding.Unblind(blindk,blind.getUnblindKey());

            SharedEncryptionKey = KeyDerivation.KDF(BigInteger.valueOf(1), k, sid);
            String tauR = KeyDerivation.KDF(BigInteger.valueOf(2), k, sid);
            ValidateKey(tauR);
        }
    }
    public void ValidateKey(String tauR){
        if (tauR.equals(decryptedData.getTau())){
            System.out.println("Great success, STAGE 3. Key is shared");
        }
        else {
            System.out.println("Something bad happened");
            throw new IllegalArgumentException();
        }
    }
}

