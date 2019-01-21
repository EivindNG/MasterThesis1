import java.security.*;

public class SignVerifyer {

    private byte[] signature;
    private PublicKey publicKey;
    private Signature sign;
    private byte[] data;
    boolean bool;

    public  SignVerifyer(byte[] signature, PublicKey publicKey, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        this.signature = signature;
        this.publicKey = publicKey;

        Signature sign = Signature.getInstance("SHA256withDSA");
        sign.initVerify(publicKey);
        sign.update(data);

        boolean bool = sign.verify(signature);

    }
}
