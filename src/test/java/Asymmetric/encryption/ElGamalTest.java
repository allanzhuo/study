package Asymmetric.encryption;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
/**
 * {@link http://www.cnblogs.com/allanzhang/}
 * @author 小卖铺的老爷爷
 *
 */
public class ElGamalTest {

	public static final String src = "laoyeye Elgamal test";
	public static void main(String[] args) 
	{
		jdkElgamal();

	}
	
	/**
	 *  
	 *  对于：“Illegal key size or default parameters”异常，是因为美国的出口限制，Sun通过权限文件（local_policy.jar、US_export_policy.jar）做了相应限制。因此存在一些问题：
	 *  Java 6 无政策限制文件：http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html
     *  Java 7 无政策限制文件：http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
     *  我的时java7，自己安装的。
     *  /Library/Java/JavaVirtualMachines/jdk1.7.0_71.jdk/Contents/Home/jre/lib/security目录下，对应覆盖local_policy.jar和US_export_policy.jar两个文件。
     *  
     *  切换到%JDK_Home%\jre\lib\security目录下，对应覆盖local_policy.jar和US_export_policy.jar两个文件。同时，你可能有必要在%JRE_Home%\lib\security目录下，也需要对应覆盖这两个文件。
	 */
	
	// jdk实现：“公钥加密，私钥解密” ， 因为Elgamal不支持“私钥加密、公钥解密”。
	public static void jdkElgamal()
	{		
		try 
		{
			// 加入对BouncyCastle支持  
			Security.addProvider(new BouncyCastleProvider());
			
			// 初始化密钥
			AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("Elgamal");
			// 初始化参数生成器
			algorithmParameterGenerator.init(256);
			// 生成算法参数
			AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();
			// 构建参数材料
			//JDK没有提供对ei的支持，但是jce框架提供了构建秘钥对的方式DHParameterSpec
			DHParameterSpec dhParameterSpec = (DHParameterSpec)algorithmParameters.getParameterSpec(DHParameterSpec.class);
			// 实例化密钥对生成器
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Elgamal");	
			// 初始化密钥对生成器  
			keyPairGenerator.initialize(dhParameterSpec, new SecureRandom());
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			// 公钥
			PublicKey elGamalPublicKey = keyPair.getPublic();
			// 私钥 
			PrivateKey elGamalPrivateKey = keyPair.getPrivate();
			System.out.println("Public Key:" + Base64.encodeBase64String(elGamalPublicKey.getEncoded()));
			System.out.println("Private Key:" + Base64.encodeBase64String(elGamalPrivateKey.getEncoded()));
			// 初始化公钥  
	        // 密钥材料转换
			X509EncodedKeySpec x509EncodedKeySpec2 = new X509EncodedKeySpec(elGamalPublicKey.getEncoded());
			// 实例化密钥工厂
			KeyFactory keyFactory = KeyFactory.getInstance("Elgamal");
			// 产生公钥
			PublicKey publicKey2 = keyFactory.generatePublic(x509EncodedKeySpec2);
			// 数据加密 
			// Cipher cipher = Cipher.getInstance("Elgamal");
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm()); 
			cipher.init(Cipher.ENCRYPT_MODE, publicKey2);
			byte[] result2 = cipher.doFinal(src.getBytes());
			System.out.println("Elgamal ---- 加密:" + Base64.encodeBase64String(result2));
			// 数据解密
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec5 = new PKCS8EncodedKeySpec(elGamalPrivateKey.getEncoded());
			keyFactory = KeyFactory.getInstance("Elgamal");
			PrivateKey privateKey5 = keyFactory.generatePrivate(pkcs8EncodedKeySpec5);
//			Cipher cipher5 = Cipher.getInstance("Elgamal");
			Cipher cipher5 = Cipher.getInstance(keyFactory.getAlgorithm()); 
			cipher5.init(Cipher.DECRYPT_MODE, privateKey5);
			byte[] result5 = cipher5.doFinal(result2);
			System.out.println("Elgamal ---- 解密:" + new String(result5));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
		
}
