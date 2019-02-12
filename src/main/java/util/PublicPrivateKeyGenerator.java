package util;

import crypto.Constants;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class PublicPrivateKeyGenerator {

    private KeyPair pair;

    public PublicPrivateKeyGenerator() throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException {

        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(Constants.CURVE_SPEC, new SecureRandom());
        this.pair = g.generateKeyPair();
        /*
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("EC","SunEC");

        kpg.initialize(ecsp);

        kp = kpg.genKeyPair();



        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        pair = keyPairGen.generateKeyPair();
*/
    }
    /*https://gist.github.com/ymnk/fec39e033394ee2ec47c
    http://armoredbarista.blogspot.com/2013/10/how-to-use-ecc-with-openjdk.html

    file:///C:/Users/Lenovo/Downloads/IJCSAI10313-20131231-164100-2544-36179.pdf
    */
    public KeyPair getPair() {
        return pair;
    }
}
