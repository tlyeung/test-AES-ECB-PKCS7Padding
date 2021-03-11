import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;

public class Main {

    static String ALGORITHM = "AES/ECB/PKCS7Padding";
    static String SECRET = "abcdefghijklmnopqrstuvwxyz123456";

//    @Test
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        System.out.println(Arrays.toString(SECRET.getBytes(StandardCharsets.UTF_8)));
        System.out.println(SECRET.getBytes(StandardCharsets.UTF_8).length);
        Security.addProvider(new BouncyCastleProvider());
        Cipher objCipher = Cipher.getInstance(ALGORITHM, "BC");
        SecretKeySpec key = new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "AES");
        objCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] arrEncrypted = objCipher.doFinal("00112233445566778899001122334455".getBytes(StandardCharsets.UTF_8));
        String hex = Hex.encodeHexString(arrEncrypted);
        System.out.println(hex);
        final String correctHex = "fd72f6cf8ea18e5aeee313016553f10fce931d728b0e73947ffc4a63e7c768edcb006a77f0bf336c2ad0e99e26102c3b";
        System.out.println("correct hex = " + correctHex);
        Assert.assertEquals(hex, correctHex);
        //fd72f6cf8ea18e5aeee313016553f10fce931d728b0e73947ffc4a63e7c768edcb006a77f0bf336c2ad0e99e26102c3b
    }
}
