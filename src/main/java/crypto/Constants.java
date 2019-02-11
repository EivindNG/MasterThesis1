package crypto;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class Constants {
    public static final ECParameterSpec CURVE_SPEC = ECNamedCurveTable.getParameterSpec("secp256r1");
}
