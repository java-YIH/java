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
	
   enum CertType {ROOT,INTER,ENDENTITY};  // 인증서의 종류: 루트인증기관 인증서, 중간 인증기관 인증서, 개인인증서
   
   // 함수 3개 선언 
   // 1. RSA 키생성 함수 - KeyPair를 리턴 
   public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
      KeyPairGenerator kpg  = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(1024);
      return kpg.genKeyPair();
   }
   
   // 2. 인증서 생성 함수 
   public static X509Certificate generateCertificate(
         X500Principal subjectDN,   // 주체
         PublicKey pubKey,         // 공개키
         PrivateKey signatureKey,   // 발급키 (발급자의 서명키)
         X509Certificate caCert,      // 발급자 인증서
         CertType type)            // 인증서 종류
      throws CertificateEncodingException,NoSuchProviderException,NoSuchAlgorithmException,SignatureException,InvalidKeyException,CertificateParsingException {
      X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
      certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis())); // 인증서 일련번호를 현재시간정보로부터 설정 
      if(type==CertType.ROOT)  // 루트인증서인 경우 발급자와 사용자가 똑같이 루트임 
         certGen.setIssuerDN(subjectDN);
      else  // 일반 사용자 인증서인 경우 발급자는 함수에 입력된 값을 이용. caCert에 있는 subjectDN을 이용  
         certGen.setIssuerDN(caCert.getSubjectX500Principal());
      certGen.setSubjectDN(subjectDN);   // 사용자(주체)의 DN을 설정 
      GregorianCalendar currentDate = new GregorianCalendar();  // 발급시간은 현재 시간으로   
      GregorianCalendar expiredDate // 만료시간, 인증서의 유효기간은 2년으로 설정했음  
         = new GregorianCalendar(currentDate.get(Calendar.YEAR)+2,currentDate.get(Calendar.MONTH),currentDate.get(Calendar.DAY_OF_MONTH));
      certGen.setNotBefore(currentDate.getTime()); // 유효기간 시작 설정
      certGen.setNotAfter(expiredDate.getTime());  // 유효기간 만료 설정 
      certGen.setPublicKey(pubKey); // 공개키 설정
      certGen.setSignatureAlgorithm("SHA1withRSAEncryption");  // 서명알고리즘 설정 
      if(type!=CertType.ROOT){   // 루트인증서인 경우의 확장영역 
         certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, 
            new AuthorityKeyIdentifierStructure(caCert));
//         certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, 
            // new SubjectKeyIdentifierStructure(pubKey));
      }
      if(type!=CertType.ENDENTITY){   // 중간 인증기관인 경우의 확장영역. 키의 사용용도를 전자서명, 인증서 서명, CRL 서명의 용도로 사용할 수 있음  
         certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
         certGen.addExtension(X509Extensions.KeyUsage, true, 
               new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
      }
      else  // 일반 사용자인 경우의 확장영역. 키의 사용용도는 전자서명용, 키암호화용으로 사용 가능  
         certGen.addExtension(X509Extensions.KeyUsage, true, 
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
      return certGen.generate(signatureKey,"BC");  // 인증서를 생성하여 결과로 리턴 
   }
   
   // 3. CRL 생성 함수. CRL은 인증기관이 생성하여 공표  
   public static X509CRL generateCRL(
         X509Certificate caCert,      // CRL 발급자 인증서
         PrivateKey signatureKey,   // CRL 발급자 서명키
         BigInteger serialNumber)   // 폐지할 인증서 일련번호
      throws CRLException,NoSuchProviderException,NoSuchAlgorithmException,SignatureException,InvalidKeyException{
      X509V2CRLGenerator crlGen = new X509V2CRLGenerator();  // CRL을 위한 변수명 설정 
      crlGen.setIssuerDN(caCert.getSubjectX500Principal());  // CRL의 발급자는 인증기관  
      GregorianCalendar currentDate = new GregorianCalendar(); // 발급시간 
      GregorianCalendar nextDate   // 다음 업데이트 시간 
         = new GregorianCalendar(currentDate.get(Calendar.YEAR)+1,(currentDate.get(Calendar.MONTH)+1)%12,currentDate.get(Calendar.DAY_OF_MONTH));
      crlGen.setThisUpdate(currentDate.getTime());
      crlGen.setNextUpdate(nextDate.getTime());
      crlGen.setSignatureAlgorithm("SHA1withRSAEncryption");  // 서명알고리즘 설정 
      if(serialNumber!=null)   // 폐지할 인증서의 일련번호를 엔트리에 추가 
         crlGen.addCRLEntry(serialNumber, currentDate.getTime(), 
               CRLReason.superseded);
      return crlGen.generate(signatureKey,"BC");   // CRL을 생성하여 출력 
   }
   
   
   public static void main(String[] args) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
      // BouncyCastle Provider 추가
      Security.addProvider(new BouncyCastleProvider());  // 프로바이더 추가 
      
      // 1. 키생성 및 인증서 발급
      // 루트인증기관 인증서는 자신의 개인키를 이용하여 발행  
      // 중간인증기관의 인증서는 루트인증기관의 개인키를 이용하여 발행
      // 개인의 인증서는 중간인증기관의 개인키를 이용하여 발행
      System.out.println("* 1. 인증서 생성 ");
      
      try{
         KeyPair rootKeyPair = generateRSAKeyPair();  // 루트인증기관 키생성 및 인증서 발급
         X509Certificate rootCert = generateCertificate(
               new X500Principal("C=KR,CN=ROOT"), rootKeyPair.getPublic(),
               rootKeyPair.getPrivate(), null, CertType.ROOT);
         System.out.println("- 루트인증기관 인증서 ");
         //System.out.println(rootCert);
         KeyPair interKeyPair = generateRSAKeyPair();  // 중간인증기관의 키생성 및 인증서 발급 
         X509Certificate interCert = generateCertificate(
               new X500Principal("C=KR,CN=INTER"), interKeyPair.getPublic(),
               rootKeyPair.getPrivate(), rootCert, CertType.INTER);
         System.out.println("- 중간인증기관 인증서 ");
         //System.out.println(interCert);
         KeyPair aliceKeyPair = generateRSAKeyPair();  // 사용자 Alice의 키생성 및 인증서 발급 
         X509Certificate aliceCert = generateCertificate(
               new X500Principal("C=KR,O=KUT,OU=IME,CN=Alice"), aliceKeyPair.getPublic(),
               interKeyPair.getPrivate(), interCert, CertType.ENDENTITY);
         System.out.println("- 사용자 Alice의 인증서 ");
         //System.out.println(aliceCert);
         KeyPair bobKeyPair = generateRSAKeyPair();   // 사용자 Bob의 키생성 및 인증서 발급 
         X509Certificate bobCert = generateCertificate(
               new X500Principal("C=KR,CN=Bob"), bobKeyPair.getPublic(),
               interKeyPair.getPrivate(), interCert, CertType.ENDENTITY);
         System.out.println("- 사용자 Bob의 인증서 ");
         //System.out.println(bobCert);
         System.out.println("Bob의 인증서의 일련번호: "+bobCert.getSerialNumber());
         
         // 1.1 인증서의 유효성 검증 (서명 검증)
         System.out.println("1.1 인증서의 유효성 검증 (서명검증) : 에러메시지가 나타나지 않으면 유효한 것임");
         rootCert.verify(rootKeyPair.getPublic());  // 루트인증기관의 인증서 유효성 검증, 루트인증기관의 공개키 이용
         interCert.verify(rootKeyPair.getPublic());  // 중간인증기관의 인증서 유효성 검증, 루트인증기관의 공개키 이용
         aliceCert.verify(interKeyPair.getPublic());  // 사용자의 인증서 유효성 검증, 중간인증기관의 공개키 이용
         bobCert.verify(interKeyPair.getPublic());  // 사용자의 인증서 유효성 검증, 중간인증기관의 공개키 이용
         
         // 1.2 인증서의 유효성 검증 (유효기간 검증) 
         System.out.println("1.2 인증서의 유효성 검증 (유효기간 검증) : 에러메시지가 나타나지 않으면 유효한 것임");
         try{
            aliceCert.checkValidity(new Date());  // 현재시간과 유효기간의 비교 
         }
         catch(CertificateExpiredException cee){   // 유효기간이 지난 경우 에러메시지 
            cee.printStackTrace();
         }
         catch(CertificateNotYetValidException cnyve){  // 유효기간이 아직 시작되지 않은 경우 에러메시지 
            cnyve.printStackTrace();
         }
         aliceCert.verify(interKeyPair.getPublic());  // Alice 인증서의 서명 검증, 중간인증기관의 공개키 이용  
         System.out.println();
         
         // 2. 인증서취소목록(CRL) 생성 
         // 루트인증기관의 CRL 생성 
         X509CRL rootCRL = generateCRL(rootCert,rootKeyPair.getPrivate(),null);
         // 중간인증기관의 CRL 생성 - 취소된 인증서 없음   
         X509CRL interCRL = generateCRL(interCert,interKeyPair.getPrivate(),null);
         // 중간인증기관의 CRL 생성 - Bob의 키를 취소시키기 위해 Bob의 인증서 일련번호를 추가
         //X509CRL interCRL = generateCRL(interCert,interKeyPair.getPrivate(),bobCert.getSerialNumber());
         
         System.out.println("* 2. 인증서취소목록(CRL) 생성 ");
         System.out.println("- 루트인증기관 CRL ");
         //System.out.println(rootCRL);
         System.out.println("- 중간인증기관 CRL ");
         //System.out.println(interCRL);
         System.out.println(" 취소된 인증서: "+interCRL.getRevokedCertificates());

         // 2.1 CRL의 유효성 검증 
         System.out.println("2.1 CRL의 유효성 검증 : 에러메시지가 나타나지 않으면 유효한 것임");
         rootCRL.verify(rootKeyPair.getPublic());     
         interCRL.verify(interKeyPair.getPublic());
         System.out.println();
         
         // 3. 인증서의 파일 처리  
         // 3.1 Alice의 인증서를 파일로 저장
         System.out.println("* 3. 인증서의 파일 처리 ");
         System.out.println("3.1  인증서를 파일로 저장 ");
         System.out.println("- Alice 인증서 : 생성 후");
         //System.out.println(aliceCert);   // 인증서 내용을 화면에 표시 
         System.out.println("- Alice 공개키 : 생성 후 ");
         System.out.println(aliceCert.getPublicKey());  // 공개키 내용을 화면에 표시  
         FileOutputStream fos = new FileOutputStream(new File("aliceCert.der")); 
         fos.write(aliceCert.getEncoded());  // 파일로 저장 
         fos.close();
         
         // 3.2 Alice의 인증서를 파일에서 읽어오기 
         System.out.println("* 3.2 인증서를 파일에서 읽어오기 ");
         CertificateFactory cf = CertificateFactory.getInstance("X.509");
         FileInputStream fis = new FileInputStream(new File("aliceCert.der"));
         X509Certificate cert = (X509Certificate)cf.generateCertificate(fis);  // 파일에서 읽어서 인증서 형식으로 할당 
         fis.close();
         System.out.println("- Alice 인증서 : 파일에서 읽어온 것 ");
         //System.out.println(cert);
         System.out.println("- Alice 공개키 : 파일에서 읽어온 것 ");
         System.out.println(cert.getPublicKey()); 
         System.out.println();
         
         // 4. 개인키의 파일 처리
         // 개인키는 암호화하여 저장해야 하며 암호화를 위한 키 코드가 필요 
         System.out.println("* 4. 개인키의 파일 처리 ");
         
         // 4.1 개인키를 파일에 저장하기  
         System.out.println("* 4.1 개인키의 파일 저장 (암호화하여 저장) ");
         System.out.println(" - Alice 개인키 : 생성 후 ");
         System.out.println(aliceKeyPair.getPrivate());    // 생성된 그대로 화면에 표시       

         String secretkey="SuperSecretKey";  // 개인키 암호화 저장을 위한 비밀키 
         char[] code = secretkey.toCharArray();
         // 이 소프트웨어를 여러 사용자가 사용하게 되는 경우 키 코드를 사용자 입력으로 받을 수 있도록 변경할 필요 
         KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());  // 키스토어라는 형태로 저장하게 됨 
         ks.load(null,null);
         
         X509Certificate[] chain = new X509Certificate[3];  // 키스토어에 저장시 인증체인 정보 필요. 루트로부터 사용자까지의 인증서 정보  
         chain[0] = aliceCert;  // 사용자 인증서 
         chain[1] = interCert;  // 중간인증기관 인증서 (중간인증기관이 Alice에게 인증서를 발급) 
         chain[2] = rootCert;  // 루트인증기관 인증서 (루트인증기관이 중간인증기관에게 인증서를 발급) 
         ks.setKeyEntry("AlicePrivateKeyAlias",aliceKeyPair.getPrivate(),code,chain); // 필요한 정보를 키스토어에 암호화하여 저장 
         fos = new FileOutputStream(new File("alicePriv.key"));   
         ks.store(fos,code);  // 키스토어의 내용을 code로 암호화하여 파일로 저장 
         fos.close();
         
         // 4.2 개인키를 파일에서 읽어오기 
         // 개인키를 읽어오기 위해서는 복호화를 위해 키 코드가 필요 
         System.out.println("* 4.2 개인키를 파일에서 읽어오기 ");
         fis = new FileInputStream(new File("alicePriv.key"));
         ks = KeyStore.getInstance(KeyStore.getDefaultType());
         ks.load(fis,code);  // 파일에서 읽어와서 키스토어에 로드 
         fis.close();
         PrivateKey alicePrivateKey = (PrivateKey)ks.getKey("AlicePrivateKeyAlias",code); // 키스토어에서 개인키를 읽어올때 암호화 키 코드 필요 
         System.out.println(" - Alice 개인키 : 파일에서 읽어온 것 ");
         System.out.println(alicePrivateKey);
         System.out.println();
         
         // 5. RSA 암호화 /복호화   (송신자 Bob이 수신자 Alice에게 파일 전송)  
         System.out.println("* 5. RSA 암호화 / 복호화  (송신자 Bob이 수신자 Alice에게 암호화된 메시지 전송)");
         // 5.1 RSA 암호화 - 인증서에 저장된 공개키 이용  

         System.out.println(" 5.1 Bob은 Alice의 인증서에서 읽어온 공개키로 RSA 암호화 ");
         String plaintext = "Hello world!";
         System.out.println(" 평문 : "+plaintext);
         byte[] t0 = plaintext.getBytes();
           Cipher cipher = Cipher.getInstance("RSA");
           cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
           byte[] b0 = cipher.doFinal(t0);
           System.out.println("암호문 : " + ByteUtils.toHexString(b0));
                    
         // 5.2 RSA 복호화 - 개인키 파일에서 읽어온 개인키 이용   
         System.out.println(" 5.2 Alice는 자신의 개인키 파일에서 읽어온 개인키로 RSA 복호화 ");
           cipher.init(Cipher.DECRYPT_MODE, alicePrivateKey);
           byte[] b1 = cipher.doFinal(b0);
           System.out.println(" 복호화된 평문 : "+ new String(b1)); 
           System.out.println();           
           
           // 6. RSA 서명 / 검증   (송신자 Alice가 수신자 Bob에게 서명된 메시지 전송 )  
            System.out.println("* 6. RSA 서명 / 검증   (Alice가 Bob에게 서명된 메시지 전송 )");

            // 6.1 RSA 서명  (Alice의 개인키 이용)    
            System.out.println(" 6.1 RSA 서명 (Alice의 개인키로 서명)");
            String sigData="전자서명 테스트";
            byte[] data = sigData.getBytes("UTF8");
            System.out.println(" Plaintext : "+sigData);         
            Signature sig = Signature.getInstance("MD5WithRSA");
            fis = new FileInputStream(new File("alicePriv.key"));
         ks = KeyStore.getInstance(KeyStore.getDefaultType());
         ks.load(fis,code);  // 파일에서 읽어와서 키스토어에 로드 
         fis.close();
         PrivateKey alicePrivateKey1 = (PrivateKey)ks.getKey("AlicePrivateKeyAlias",code); // 키스토어에서 개인키를 읽어올때 암호화 키 코드 필요
            sig.initSign(alicePrivateKey1);
            sig.update(data);
            byte[] signatureBytes = sig.sign();
            System.out.println(" 서명문 : " + ByteUtils.toHexString(signatureBytes));
            
            // 6.2 RSA 서명 검증  (Alice의 인증서에 있는 공개키 이용)    
            System.out.println(" 6.2 RSA 서명검증 (Alice의 공개키로 서명검증)");
            CertificateFactory cf1 = CertificateFactory.getInstance("X.509");
         FileInputStream fis1 = new FileInputStream(new File("aliceCert.der"));
         X509Certificate cert1 = (X509Certificate)cf1.generateCertificate(fis1);  // 파일에서 읽어서 인증서 형식으로 할당 
         fis1.close();
         sig.initVerify(cert1.getPublicKey());
         sig.update(data);
         System.out.println(" Verification: "+sig.verify(signatureBytes));  // 서명결과 출력 
         System.out.println();   
         
         // 7. 인증서 폐지 여부 검사
         System.out.println("* 7. 인증서 폐지 여부 검사   ");
         X509CRLEntry entry = interCRL.getRevokedCertificate(bobCert.getSerialNumber()); // 지정된 인증서의 serialNumber를 가지는 CRL 엔트리를 취득합니다 (존재하는 경우). 
         if(entry!=null){
            System.out.printf("폐지된 인증서 번호: %d%n", entry.getSerialNumber());
            if(entry.getCertificateIssuer()==null)
               System.out.printf("발급자: %s%n", interCRL.getIssuerX500Principal());
            else System.out.printf("발급자: %s%n", entry.getCertificateIssuer());
         }
         System.out.println();
                  
         // 8. CRL 파일 처리 
         System.out.println("* 8. CRL 파일 처리  ");
         // 8.1 CRL 파일 저장 
         System.out.println(" 8.1 CRL 파일 저장  ");
         fos = new FileOutputStream(new File("inter.crl"));
         fos.write(interCRL.getEncoded());
         fos.close();

         // 8.2 CRL 파일에서 읽어오기  
         System.out.println(" 8.2 CRL 파일에서 읽어오기   ");
         cf = CertificateFactory.getInstance("X.509");
         fis = new FileInputStream(new File("inter.crl"));
         X509CRL newcrl = (X509CRL)cf.generateCRL(fis);
         fis.close();
         entry = newcrl.getRevokedCertificate(bobCert.getSerialNumber());
         System.out.println("* CRL : 저장 후 읽어온 것 ");
         if(entry!=null){
            System.out.printf("폐기된 인증서 번호: %d%n", entry.getSerialNumber());
            if(entry.getCertificateIssuer()==null)
               System.out.printf("발급자: %s%n", newcrl.getIssuerX500Principal());
            else System.out.printf("발급자: %s%n", entry.getCertificateIssuer());
         }
         System.out.println();
         
         // 9. 인증서 디렉토리 생성
         System.out.println(" 9. 인증서 디렉토리 생성 ");
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
         
         // 10. 인증 경로 생성 및 확인
         System.out.println(" 10. 인증 경로 생성 및 확인  ");
         System.out.println(" - 유효한 인증서인 경우 경로확인 결과를 표시  ");
         System.out.println(" - 유효하지 않은 인증서인 경우 에러메시지를 표시  ");
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
            System.out.println("* 인증 경로");
            //System.out.println(e.getCertPath());
            System.out.println("* 검증 실패 사유");
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
   