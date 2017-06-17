package server;


import java.io.File;
import java.io.FileInputStream;  
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;


import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
// import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;



@SuppressWarnings("deprecation")
public class  Certification {
	
   enum CertType {ROOT,INTER,ENDENTITY};  // �������� ����: ��Ʈ������� ������, �߰� ������� ������, ����������
   
   // �Լ� 3�� ���� 
   // 1. RSA Ű���� �Լ� - KeyPair�� ���� 
   public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
      KeyPairGenerator kpg  = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(1024);
      return kpg.genKeyPair();
   }
   
   // 2. ������ ���� �Լ� 
   public static X509Certificate generateCertificate(
         X500Principal subjectDN,   // ��ü
         PublicKey pubKey,         // ����Ű
         PrivateKey signatureKey,   // �߱�Ű (�߱����� ����Ű)
         X509Certificate caCert,      // �߱��� ������
         CertType type)            // ������ ����
      throws CertificateEncodingException,NoSuchProviderException,NoSuchAlgorithmException,SignatureException,InvalidKeyException,CertificateParsingException {
      X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
      certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis())); // ������ �Ϸù�ȣ�� ����ð������κ��� ���� 
      if(type==CertType.ROOT)  // ��Ʈ�������� ��� �߱��ڿ� ����ڰ� �Ȱ��� ��Ʈ�� 
         certGen.setIssuerDN(subjectDN);
      else  // �Ϲ� ����� �������� ��� �߱��ڴ� �Լ��� �Էµ� ���� �̿�. caCert�� �ִ� subjectDN�� �̿�  
         certGen.setIssuerDN(caCert.getSubjectX500Principal());
      certGen.setSubjectDN(subjectDN);   // �����(��ü)�� DN�� ���� 
      GregorianCalendar currentDate = new GregorianCalendar();  // �߱޽ð��� ���� �ð�����   
      GregorianCalendar expiredDate // ����ð�, �������� ��ȿ�Ⱓ�� 2������ ��������  
         = new GregorianCalendar(currentDate.get(Calendar.YEAR)+2,currentDate.get(Calendar.MONTH),currentDate.get(Calendar.DAY_OF_MONTH));
      certGen.setNotBefore(currentDate.getTime()); // ��ȿ�Ⱓ ���� ����
      certGen.setNotAfter(expiredDate.getTime());  // ��ȿ�Ⱓ ���� ���� 
      certGen.setPublicKey(pubKey); // ����Ű ����
      certGen.setSignatureAlgorithm("SHA1withRSAEncryption");  // ����˰��� ���� 
      if(type!=CertType.ROOT){   // ��Ʈ�������� ����� Ȯ�念�� 
         certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, 
            new AuthorityKeyIdentifierStructure(caCert));
//         certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, 
            // new SubjectKeyIdentifierStructure(pubKey));
      }
      if(type!=CertType.ENDENTITY){   // �߰� ��������� ����� Ȯ�念��. Ű�� ���뵵�� ���ڼ���, ������ ����, CRL ������ �뵵�� ����� �� ����  
         certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
         certGen.addExtension(X509Extensions.KeyUsage, true, 
               new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
      }
      else  // �Ϲ� ������� ����� Ȯ�念��. Ű�� ���뵵�� ���ڼ����, Ű��ȣȭ������ ��� ����  
         certGen.addExtension(X509Extensions.KeyUsage, true, 
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
      return certGen.generate(signatureKey,"BC");  // �������� �����Ͽ� ����� ���� 
   }
   
   // 3. CRL ���� �Լ�. CRL�� ��������� �����Ͽ� ��ǥ  
   public static X509CRL generateCRL(
         X509Certificate caCert,      // CRL �߱��� ������
         PrivateKey signatureKey,   // CRL �߱��� ����Ű
         BigInteger serialNumber)   // ������ ������ �Ϸù�ȣ
      throws CRLException,NoSuchProviderException,NoSuchAlgorithmException,SignatureException,InvalidKeyException{
      X509V2CRLGenerator crlGen = new X509V2CRLGenerator();  // CRL�� ���� ������ ���� 
      crlGen.setIssuerDN(caCert.getSubjectX500Principal());  // CRL�� �߱��ڴ� �������  
      GregorianCalendar currentDate = new GregorianCalendar(); // �߱޽ð� 
      GregorianCalendar nextDate   // ���� ������Ʈ �ð� 
         = new GregorianCalendar(currentDate.get(Calendar.YEAR)+1,(currentDate.get(Calendar.MONTH)+1)%12,currentDate.get(Calendar.DAY_OF_MONTH));
      crlGen.setThisUpdate(currentDate.getTime());
      crlGen.setNextUpdate(nextDate.getTime());
      crlGen.setSignatureAlgorithm("SHA1withRSAEncryption");  // ����˰��� ���� 
      if(serialNumber!=null)   // ������ �������� �Ϸù�ȣ�� ��Ʈ���� �߰� 
         crlGen.addCRLEntry(serialNumber, currentDate.getTime(), 
               CRLReason.superseded);
      return crlGen.generate(signatureKey,"BC");   // CRL�� �����Ͽ� ��� 
   }
   
   
   public static void main(String[] args) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
      // BouncyCastle Provider �߰�
      Security.addProvider(new BouncyCastleProvider());  // ���ι��̴� �߰� 
      
      // 1. Ű���� �� ������ �߱�
      // ��Ʈ������� �������� �ڽ��� ����Ű�� �̿��Ͽ� ����  
      // �߰���������� �������� ��Ʈ��������� ����Ű�� �̿��Ͽ� ����
      // ������ �������� �߰���������� ����Ű�� �̿��Ͽ� ����
      System.out.println("* 1. ������ ���� ");
      
      try{
         KeyPair rootKeyPair = generateRSAKeyPair();  // ��Ʈ������� Ű���� �� ������ �߱�
         X509Certificate rootCert = generateCertificate(
               new X500Principal("C=KR,CN=ROOT"), rootKeyPair.getPublic(),
               rootKeyPair.getPrivate(), null, CertType.ROOT);
         System.out.println("- ��Ʈ������� ������ ");
         //System.out.println(rootCert);
         KeyPair interKeyPair = generateRSAKeyPair();  // �߰���������� Ű���� �� ������ �߱� 
         X509Certificate interCert = generateCertificate(
               new X500Principal("C=KR,CN=INTER"), interKeyPair.getPublic(),
               rootKeyPair.getPrivate(), rootCert, CertType.INTER);
         System.out.println("- �߰�������� ������ ");
         //System.out.println(interCert);
         KeyPair aliceKeyPair = generateRSAKeyPair();  // ����� Alice�� Ű���� �� ������ �߱� 
         X509Certificate aliceCert = generateCertificate(
               new X500Principal("C=KR,O=KUT,OU=IME,CN=Alice"), aliceKeyPair.getPublic(),
               interKeyPair.getPrivate(), interCert, CertType.ENDENTITY);
         System.out.println("- ����� Alice�� ������ ");
         //System.out.println(aliceCert);
         KeyPair bobKeyPair = generateRSAKeyPair();   // ����� Bob�� Ű���� �� ������ �߱� 
         X509Certificate bobCert = generateCertificate(
               new X500Principal("C=KR,CN=Bob"), bobKeyPair.getPublic(),
               interKeyPair.getPrivate(), interCert, CertType.ENDENTITY);
         System.out.println("- ����� Bob�� ������ ");
         //System.out.println(bobCert);
         System.out.println("Bob�� �������� �Ϸù�ȣ: "+bobCert.getSerialNumber());
         
         // 1.1 �������� ��ȿ�� ���� (���� ����)
         System.out.println("1.1 �������� ��ȿ�� ���� (�������) : �����޽����� ��Ÿ���� ������ ��ȿ�� ����");
         rootCert.verify(rootKeyPair.getPublic());  // ��Ʈ��������� ������ ��ȿ�� ����, ��Ʈ��������� ����Ű �̿�
         interCert.verify(rootKeyPair.getPublic());  // �߰���������� ������ ��ȿ�� ����, ��Ʈ��������� ����Ű �̿�
         aliceCert.verify(interKeyPair.getPublic());  // ������� ������ ��ȿ�� ����, �߰���������� ����Ű �̿�
         bobCert.verify(interKeyPair.getPublic());  // ������� ������ ��ȿ�� ����, �߰���������� ����Ű �̿�
         
         // 1.2 �������� ��ȿ�� ���� (��ȿ�Ⱓ ����) 
         System.out.println("1.2 �������� ��ȿ�� ���� (��ȿ�Ⱓ ����) : �����޽����� ��Ÿ���� ������ ��ȿ�� ����");
         try{
            aliceCert.checkValidity(new Date());  // ����ð��� ��ȿ�Ⱓ�� �� 
         }
         catch(CertificateExpiredException cee){   // ��ȿ�Ⱓ�� ���� ��� �����޽��� 
            cee.printStackTrace();
         }
         catch(CertificateNotYetValidException cnyve){  // ��ȿ�Ⱓ�� ���� ���۵��� ���� ��� �����޽��� 
            cnyve.printStackTrace();
         }
         aliceCert.verify(interKeyPair.getPublic());  // Alice �������� ���� ����, �߰���������� ����Ű �̿�  
         System.out.println();
         
         // 2. ��������Ҹ��(CRL) ���� 
         // ��Ʈ��������� CRL ���� 
         X509CRL rootCRL = generateCRL(rootCert,rootKeyPair.getPrivate(),null);
         // �߰���������� CRL ���� - ��ҵ� ������ ����   
         X509CRL interCRL = generateCRL(interCert,interKeyPair.getPrivate(),null);
         // �߰���������� CRL ���� - Bob�� Ű�� ��ҽ�Ű�� ���� Bob�� ������ �Ϸù�ȣ�� �߰�
         //X509CRL interCRL = generateCRL(interCert,interKeyPair.getPrivate(),bobCert.getSerialNumber());
         
         System.out.println("* 2. ��������Ҹ��(CRL) ���� ");
         System.out.println("- ��Ʈ������� CRL ");
         //System.out.println(rootCRL);
         System.out.println("- �߰�������� CRL ");
         //System.out.println(interCRL);
         System.out.println(" ��ҵ� ������: "+interCRL.getRevokedCertificates());

         // 2.1 CRL�� ��ȿ�� ���� 
         System.out.println("2.1 CRL�� ��ȿ�� ���� : �����޽����� ��Ÿ���� ������ ��ȿ�� ����");
         rootCRL.verify(rootKeyPair.getPublic());     
         interCRL.verify(interKeyPair.getPublic());
         System.out.println();
         
         // 3. �������� ���� ó��  
         // 3.1 Alice�� �������� ���Ϸ� ����
         System.out.println("* 3. �������� ���� ó�� ");
         System.out.println("3.1  �������� ���Ϸ� ���� ");
         System.out.println("- Alice ������ : ���� ��");
         //System.out.println(aliceCert);   // ������ ������ ȭ�鿡 ǥ�� 
         System.out.println("- Alice ����Ű : ���� �� ");
         System.out.println(aliceCert.getPublicKey());  // ����Ű ������ ȭ�鿡 ǥ��  
         FileOutputStream fos = new FileOutputStream(new File("aliceCert.der")); 
         fos.write(aliceCert.getEncoded());  // ���Ϸ� ���� 
         fos.close();
         
         // 3.2 Alice�� �������� ���Ͽ��� �о���� 
         System.out.println("* 3.2 �������� ���Ͽ��� �о���� ");
         CertificateFactory cf = CertificateFactory.getInstance("X.509");
         FileInputStream fis = new FileInputStream(new File("aliceCert.der"));
         X509Certificate cert = (X509Certificate)cf.generateCertificate(fis);  // ���Ͽ��� �о ������ �������� �Ҵ� 
         fis.close();
         System.out.println("- Alice ������ : ���Ͽ��� �о�� �� ");
         //System.out.println(cert);
         System.out.println("- Alice ����Ű : ���Ͽ��� �о�� �� ");
         System.out.println(cert.getPublicKey()); 
         System.out.println();
         
         // 4. ����Ű�� ���� ó��
         // ����Ű�� ��ȣȭ�Ͽ� �����ؾ� �ϸ� ��ȣȭ�� ���� Ű �ڵ尡 �ʿ� 
         System.out.println("* 4. ����Ű�� ���� ó�� ");
         
         // 4.1 ����Ű�� ���Ͽ� �����ϱ�  
         System.out.println("* 4.1 ����Ű�� ���� ���� (��ȣȭ�Ͽ� ����) ");
         System.out.println(" - Alice ����Ű : ���� �� ");
         System.out.println(aliceKeyPair.getPrivate());    // ������ �״�� ȭ�鿡 ǥ��       

         String secretkey="SuperSecretKey";  // ����Ű ��ȣȭ ������ ���� ���Ű 
         char[] code = secretkey.toCharArray();
         // �� ����Ʈ��� ���� ����ڰ� ����ϰ� �Ǵ� ��� Ű �ڵ带 ����� �Է����� ���� �� �ֵ��� ������ �ʿ� 
         KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());  // Ű������� ���·� �����ϰ� �� 
         ks.load(null,null);
         
         X509Certificate[] chain = new X509Certificate[3];  // Ű���� ����� ����ü�� ���� �ʿ�. ��Ʈ�κ��� ����ڱ����� ������ ����  
         chain[0] = aliceCert;  // ����� ������ 
         chain[1] = interCert;  // �߰�������� ������ (�߰���������� Alice���� �������� �߱�) 
         chain[2] = rootCert;  // ��Ʈ������� ������ (��Ʈ��������� �߰������������ �������� �߱�) 
         ks.setKeyEntry("AlicePrivateKeyAlias",aliceKeyPair.getPrivate(),code,chain); // �ʿ��� ������ Ű���� ��ȣȭ�Ͽ� ���� 
         fos = new FileOutputStream(new File("alicePriv.key"));   
         ks.store(fos,code);  // Ű������� ������ code�� ��ȣȭ�Ͽ� ���Ϸ� ���� 
         fos.close();
         
         // 4.2 ����Ű�� ���Ͽ��� �о���� 
         // ����Ű�� �о���� ���ؼ��� ��ȣȭ�� ���� Ű �ڵ尡 �ʿ� 
         System.out.println("* 4.2 ����Ű�� ���Ͽ��� �о���� ");
         fis = new FileInputStream(new File("alicePriv.key"));
         ks = KeyStore.getInstance(KeyStore.getDefaultType());
         ks.load(fis,code);  // ���Ͽ��� �о�ͼ� Ű���� �ε� 
         fis.close();
         PrivateKey alicePrivateKey = (PrivateKey)ks.getKey("AlicePrivateKeyAlias",code); // Ű������ ����Ű�� �о�ö� ��ȣȭ Ű �ڵ� �ʿ� 
         System.out.println(" - Alice ����Ű : ���Ͽ��� �о�� �� ");
         System.out.println(alicePrivateKey);
         System.out.println();
         
         // 5. RSA ��ȣȭ /��ȣȭ   (�۽��� Bob�� ������ Alice���� ���� ����)  
         System.out.println("* 5. RSA ��ȣȭ / ��ȣȭ  (�۽��� Bob�� ������ Alice���� ��ȣȭ�� �޽��� ����)");
         // 5.1 RSA ��ȣȭ - �������� ����� ����Ű �̿�  

         System.out.println(" 5.1 Bob�� Alice�� ���������� �о�� ����Ű�� RSA ��ȣȭ ");
         String plaintext = "Hello world!";
         System.out.println(" �� : "+plaintext);
         byte[] t0 = plaintext.getBytes();
           Cipher cipher = Cipher.getInstance("RSA");
           cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
           byte[] b0 = cipher.doFinal(t0);
           System.out.println("��ȣ�� : " + ByteUtils.toHexString(b0));
                    
         // 5.2 RSA ��ȣȭ - ����Ű ���Ͽ��� �о�� ����Ű �̿�   
         System.out.println(" 5.2 Alice�� �ڽ��� ����Ű ���Ͽ��� �о�� ����Ű�� RSA ��ȣȭ ");
           cipher.init(Cipher.DECRYPT_MODE, alicePrivateKey);
           byte[] b1 = cipher.doFinal(b0);
           System.out.println(" ��ȣȭ�� �� : "+ new String(b1)); 
           System.out.println();           
           
           // 6. RSA ���� / ����   (�۽��� Alice�� ������ Bob���� ����� �޽��� ���� )  
            System.out.println("* 6. RSA ���� / ����   (Alice�� Bob���� ����� �޽��� ���� )");

            // 6.1 RSA ����  (Alice�� ����Ű �̿�)    
            System.out.println(" 6.1 RSA ���� (Alice�� ����Ű�� ����)");
            String sigData="���ڼ��� �׽�Ʈ";
            byte[] data = sigData.getBytes("UTF8");
            System.out.println(" Plaintext : "+sigData);         
            Signature sig = Signature.getInstance("MD5WithRSA");
            fis = new FileInputStream(new File("alicePriv.key"));
         ks = KeyStore.getInstance(KeyStore.getDefaultType());
         ks.load(fis,code);  // ���Ͽ��� �о�ͼ� Ű���� �ε� 
         fis.close();
         PrivateKey alicePrivateKey1 = (PrivateKey)ks.getKey("AlicePrivateKeyAlias",code); // Ű������ ����Ű�� �о�ö� ��ȣȭ Ű �ڵ� �ʿ�
            sig.initSign(alicePrivateKey1);
            sig.update(data);
            byte[] signatureBytes = sig.sign();
            System.out.println(" ���� : " + ByteUtils.toHexString(signatureBytes));
            
            // 6.2 RSA ���� ����  (Alice�� �������� �ִ� ����Ű �̿�)    
            System.out.println(" 6.2 RSA ������� (Alice�� ����Ű�� �������)");
            CertificateFactory cf1 = CertificateFactory.getInstance("X.509");
         FileInputStream fis1 = new FileInputStream(new File("aliceCert.der"));
         X509Certificate cert1 = (X509Certificate)cf1.generateCertificate(fis1);  // ���Ͽ��� �о ������ �������� �Ҵ� 
         fis1.close();
         sig.initVerify(cert1.getPublicKey());
         sig.update(data);
         System.out.println(" Verification: "+sig.verify(signatureBytes));  // ������ ��� 
         System.out.println();   
         
         // 7. ������ ���� ���� �˻�
         System.out.println("* 7. ������ ���� ���� �˻�   ");
         X509CRLEntry entry = interCRL.getRevokedCertificate(bobCert.getSerialNumber()); // ������ �������� serialNumber�� ������ CRL ��Ʈ���� ����մϴ� (�����ϴ� ���). 
         if(entry!=null){
            System.out.printf("������ ������ ��ȣ: %d%n", entry.getSerialNumber());
            if(entry.getCertificateIssuer()==null)
               System.out.printf("�߱���: %s%n", interCRL.getIssuerX500Principal());
            else System.out.printf("�߱���: %s%n", entry.getCertificateIssuer());
         }
         System.out.println();
                  
         // 8. CRL ���� ó�� 
         System.out.println("* 8. CRL ���� ó��  ");
         // 8.1 CRL ���� ���� 
         System.out.println(" 8.1 CRL ���� ����  ");
         fos = new FileOutputStream(new File("inter.crl"));
         fos.write(interCRL.getEncoded());
         fos.close();

         // 8.2 CRL ���Ͽ��� �о����  
         System.out.println(" 8.2 CRL ���Ͽ��� �о����   ");
         cf = CertificateFactory.getInstance("X.509");
         fis = new FileInputStream(new File("inter.crl"));
         X509CRL newcrl = (X509CRL)cf.generateCRL(fis);
         fis.close();
         entry = newcrl.getRevokedCertificate(bobCert.getSerialNumber());
         System.out.println("* CRL : ���� �� �о�� �� ");
         if(entry!=null){
            System.out.printf("���� ������ ��ȣ: %d%n", entry.getSerialNumber());
            if(entry.getCertificateIssuer()==null)
               System.out.printf("�߱���: %s%n", newcrl.getIssuerX500Principal());
            else System.out.printf("�߱���: %s%n", entry.getCertificateIssuer());
         }
         System.out.println();
         
         // 9. ������ ���丮 ����
         System.out.println(" 9. ������ ���丮 ���� ");
         List<X509Extension> list = new ArrayList<X509Extension>();
         list.add(rootCert);
         list.add(interCert);
         list.add(aliceCert);
         list.add(bobCert);
         list.add(rootCRL);
         list.add(interCRL);
         //System.out.println(list);
         
         CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
         CertStore store = CertStore.getInstance("Collection",params);
         System.out.println();
         
         // 10. ���� ��� ���� �� Ȯ��
         System.out.println(" 10. ���� ��� ���� �� Ȯ��  ");
         System.out.println(" - ��ȿ�� �������� ��� ���Ȯ�� ����� ǥ��  ");
         System.out.println(" - ��ȿ���� ���� �������� ��� �����޽����� ǥ��  ");
         cf = CertificateFactory.getInstance("X.509");
         List<Certificate> certChain = new ArrayList<Certificate>();
         certChain.add(bobCert);
         certChain.add(interCert);
         CertPath certPath = cf.generateCertPath(certChain);
         Set<TrustAnchor> trust = Collections.singleton(new TrustAnchor(rootCert,null));
         CertPathValidator validator = CertPathValidator.getInstance("PKIX","BC");
         PKIXParameters param = new PKIXParameters(trust);
         param.addCertStore(store);
         param.setDate(new Date());
         try{
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)validator.validate(certPath,param);
            System.out.println(result);
         }
         catch(CertPathValidatorException e){
            System.out.println("* ���� ���");
            //System.out.println(e.getCertPath());
            System.out.println("* ���� ���� ����");
            System.out.println("validation failed "+e.getIndex()+" detail: "+e.getMessage());
         }   
      }
      catch(NoSuchAlgorithmException nsae){
         nsae.printStackTrace();
      }
      catch(CertificateException ce){
         ce.printStackTrace();
      }
      catch(InvalidKeyException ike){
         ike.printStackTrace();
      }
      catch(InvalidAlgorithmParameterException iape){
         iape.printStackTrace();
      }
      catch(SignatureException se){
         se.printStackTrace();
      }
      catch(NoSuchProviderException nspre){
         nspre.printStackTrace();
      }
      catch(KeyStoreException kse){
         kse.printStackTrace();
      }
      catch(UnrecoverableKeyException uke){
         uke.printStackTrace();
      }
      catch(CRLException nsae){
         nsae.printStackTrace();
      }
   }
}
   