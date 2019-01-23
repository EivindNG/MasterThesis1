package server;


import crypto.Hashing;
import initiator.Initiator;
import util.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.HashMap;

public class Server {

    private BigInteger id;
    private KeyPair SkPk;
    private KeyPairGenerationBKEM ekdk;
    private String sid;

    public Server() throws NoSuchAlgorithmException {
        PublicPrivateKeyGenerator privatepublickey = new PublicPrivateKeyGenerator();
        SkPk = privatepublickey.getPair();
        id = IdMaker.getNextId();
        PublicKeyList.getKeyList().put(id,SkPk.getPublic());
    }

    public void submitNonce(BigInteger nonce, HashMap<BigInteger, PublicKey> pid, byte[] signing, Initiator initiator) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(nonce.toByteArray());
        for (BigInteger key : pid.keySet()) {
            outputStream.write(key.toByteArray());
        }
        byte AltSammen[] = outputStream.toByteArray( );

        if (SignVerifyer.Verify(signing, PublicKeyList.getKeyList().get(initiator.getId()), AltSammen)){
            ekdk = new KeyPairGenerationBKEM();

            ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream( );
            outputStream2.write(nonce.toByteArray());
            for (BigInteger key : pid.keySet()) {
                outputStream2.write(key.toByteArray());
            }
            outputStream2.write(ekdk.getencryptionKey().toByteArray());
            byte data[] = outputStream2.toByteArray( );

            sid = sidGenerator.GenerateSid(initiator.getId(), nonce, pid, ekdk.getencryptionKey());

            initiator.checkSid(ekdk.getencryptionKey(),Signing.Sign(SkPk,data));
        }
        else{
            throw new IllegalArgumentException();
        }
    }

    public BigInteger getId() {
        return id;
    }
}
