package util;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.Serializable;

public class AESandIV implements Serializable {
    byte[] iv;
    byte[] aesKey;

    public byte[] getIv() {
        return iv;
    }

    public byte[] getAesKey() {
        return aesKey;
    }

    public AESandIV(IvParameterSpec iv, SecretKey aesKey) {
        this.iv = iv.getIV();
        this.aesKey = aesKey.getEncoded();
    }
}
