package Asymmetric.encryption;

import org.apache.commons.codec.binary.Hex;
import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
/**
 * {@link http://www.cnblogs.com/allanzhang/}
 * @author 小卖铺的老爷爷
 *
 */
public class RSATest {
    public static final String src = "laoyeye rsa";
    public static void main(String[] args) throws Exception {
        jdkRSA();
    }
    public static void jdkRSA() throws Exception {
        //初始化密钥
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);//512~65532
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //私钥加密，公钥解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
        byte[] result = cipher.doFinal(src.getBytes());
        System.out.println("**私钥加密，公钥解密**");
        System.out.println("加密：" + Hex.encodeHexString(result));
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
        result = cipher.doFinal(result);
        System.out.println("解密：" + new String(result));
    }
}