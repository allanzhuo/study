package Asymmetric.encryption;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;

import com.sun.org.apache.xalan.internal.utils.Objects;

/**
 * {@link http://www.cnblogs.com/allanzhang/}
 * @author 小卖铺的老爷爷
 *
 */
public class DH2Test {

    private static String src = "laoyeye dh";

    public static void main(String[] args) {
        jdkDH();
    }//main方法结束

    public static void jdkDH(){
        try {
            //1.初始化发送方密钥    甲方产出一对密钥（公钥、私钥）
            //甲方构建密钥对儿，将公钥(senderPublicKeyEnc)公布给乙方，将私钥保留；双方约定数据加密算法
        	//为指定的算法 DH 创建发送方密钥对生成器 KeyPairGenerator 对象
            KeyPairGenerator senderKeyPairGenerator = KeyPairGenerator.getInstance("DH");
            //为发送方密钥对生成器 KeyPairGenerator对象senderKeyPairGenerator设置生成密钥对的长度
            senderKeyPairGenerator.initialize(512);             
            //生成一个密钥对KeyPair（密钥对（公钥和私钥）持有者）;即 发送方的密钥对持有者senderKeyPair
            KeyPair senderKeyPair = senderKeyPairGenerator.generateKeyPair();            
            // 甲方公钥  
            DHPublicKey senderDhPublicKey = (DHPublicKey) senderKeyPair.getPublic();  
            // 甲方私钥  
            DHPrivateKey senderDhPrivateKey = (DHPrivateKey) senderKeyPair.getPrivate();  
            //以byte[]数组的方式存储   发送方的公钥
            byte[] senderPublicKeyEnc = senderKeyPair.getPublic().getEncoded();          

            //2.初始化接收方密钥    乙方依照甲方公钥产生乙方密钥对（公钥、私钥）
            //乙方通过甲方公钥构建密钥对儿，将公钥公布给甲方，将私钥保留

            // 2.1解析甲方公钥  
            //根据发送方公布的公钥创建一个X509EncodedKeySpec对象x509EncodedKeySpec(根据发送方公钥产生的 用于生成接收方密钥的原料)
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(senderPublicKeyEnc);
            //为指定的算法 DH 创建接收方密钥工厂对象 receiverKeyFactory  
            KeyFactory receiverKeyFactory = KeyFactory.getInstance("DH");                       
            //收方密钥工厂对象 receiverKeyFactory使用generatePublic("根据发送方公钥产生,用于生成接收方密钥的原始材料x509EncodedKeySpec")方法
            PublicKey receiverPublicKey = receiverKeyFactory.generatePublic(x509EncodedKeySpec);//接收方公钥

            // 2.2由甲方公钥构建乙方密钥 
            DHParameterSpec dhParameterSpec = ((DHPublicKey)receiverPublicKey).getParams();//从发送方解析出来的参数
            KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");
            receiverKeyPairGenerator.initialize(dhParameterSpec);//初始化receiverKeyPairGenerator
            KeyPair receiverKeyPair = receiverKeyPairGenerator.generateKeyPair();//由receiverKeyPairGenerator来生成接收方的 KeyPair  密钥对

             // 乙方公钥  
            DHPublicKey receiverDhPublicKey = (DHPublicKey) receiverKeyPair.getPublic();  
            // 乙方私钥  
            DHPrivateKey receiverDhPrivateKey = (DHPrivateKey) receiverKeyPair.getPrivate();  

            PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();//接收方私钥
            byte[] receiverPublicKeyEnc = receiverKeyPair.getPublic().getEncoded();  //以byte[]数组的方式存储   接收方的公钥

            //3.构建密钥
            //生成接收方的本地密钥
            KeyAgreement receiverKeyAgreement = KeyAgreement.getInstance("DH");
            receiverKeyAgreement.init(receiverPrivateKey);
            receiverKeyAgreement.doPhase(receiverPublicKey, true);
            //3.1用发送方公钥来生成接收方的本地密钥receiverSecretKey
            SecretKey receiverSecretKey = receiverKeyAgreement.generateSecret("DES");

            //生成发送方的本地密钥senderrSecretKey
            //重新初始化x509EncodedKeySpec
            KeyFactory senderKeyFactory = KeyFactory.getInstance("DH");
            x509EncodedKeySpec = new X509EncodedKeySpec(receiverPublicKeyEnc);//根据接收方公布的公钥创建一个X509EncodedKeySpec对象x509EncodedKeySpec(根据接收方公钥产生的 用于生成发送方密钥的原料)
            PublicKey senderPublicKey = senderKeyFactory.generatePublic(x509EncodedKeySpec);
            KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
            senderKeyAgreement.init(senderKeyPair.getPrivate());
            senderKeyAgreement.doPhase(senderPublicKey, true);
            SecretKey senderSecretKey = senderKeyAgreement.generateSecret("DES");

            //比较发送方和接收方的本地密钥是否相同
            if(Objects.equals(senderSecretKey, receiverSecretKey)){
                System.out.println("双方本地密钥相同");
            }

            //4.发送方加密
            Cipher senderCipher = Cipher.getInstance("DES");
            senderCipher.init(Cipher.ENCRYPT_MODE, senderSecretKey);
            byte[] senderEncodeResult = senderCipher.doFinal(src.getBytes());
            System.out.println("jdk dh encrypt:"+Base64.encodeBase64String(senderEncodeResult));

            //4.接收方解密
            Cipher receiverCipher = Cipher.getInstance("DES");
            receiverCipher.init(Cipher.DECRYPT_MODE, receiverSecretKey);
            byte[] receiverDecodeResult = receiverCipher.doFinal(senderEncodeResult);
            System.out.println("jdk dh decrypt:"+new String(receiverDecodeResult));


        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }//jdkDH()方法结束
}//DH类结束