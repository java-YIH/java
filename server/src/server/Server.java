package server;

import java.io.*;
import java.util.*;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import server.Certification.CertType;

import java.net.*;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


class Server{
	
	public static class Key
	{
		byte[] publicKey;
		byte[] privateKey;
		PublicKey pubKey; 
        PrivateKey priKey;     
        PrivateKey restoreFromFileKey;
	}
	public static void MakeRSAKey(Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024); 
        KeyPair keyPair = generator.generateKeyPair();
        key.pubKey = keyPair.getPublic();
        key.priKey = keyPair.getPrivate();

        
        System.out.println("=== RSA 키생성 ===");
        key.publicKey = key.pubKey.getEncoded();
        key.privateKey = key.priKey.getEncoded(); 
        
           
	}
   
	public static byte[] decrypt(PrivateKey privateKey, byte[] encryptData) throws GeneralSecurityException {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] plainData = cipher.doFinal(encryptData);
			return plainData;
			}

	public static String bytesToHex(byte[] bytes) {
	    StringBuilder sb = new StringBuilder(bytes.length * 2);
	 
	    @SuppressWarnings("resource")
		Formatter formatter = new Formatter(sb);
	    for (byte b : bytes) {
	        formatter.format("%02x", b);
	    }
	 
	    return sb.toString();
	}

	
	public static void main(String[] args) throws IOException, GeneralSecurityException{
	
	
		boolean flag=false;
		//키쌍을 가지고 있는 class 생성
		Key key = new Key();
		MakeRSAKey(key); //키 생성
		
		System.out.println(" 공개키 : "+bytesToHex(key.publicKey));
		
		//포트 개방
		ServerSocket serverSocket = new ServerSocket(8013);

		
		System.out.println("Listening...");
		Socket socket = serverSocket.accept();
		System.out.println("Client("+socket.getInetAddress()+") Connect!");
		
		//출력 스트림 생성
		OutputStream OutputClient = socket.getOutputStream();
		BufferedWriter WriteToClient = new BufferedWriter(new OutputStreamWriter(OutputClient));
		
		//입력 스트림 생성
		InputStream InputClient = socket.getInputStream();
		BufferedReader ReadFromClient = new BufferedReader(new InputStreamReader(InputClient));
	
	
		//전송을 위해 공개키를 Base64타입으로 인코딩
		Encoder encoder = Base64.getEncoder();
		String publicKey = encoder.encodeToString(key.publicKey);

		
		//공개키 전송
		WriteToClient.write(publicKey+"\n");
		WriteToClient.flush();
		
		String recvEncrptMsg=null;
	
		/********************************************인증서 관련 소스 코드 ********************************************************/
	      // BouncyCastle Provider 추가
	    Security.addProvider(new BouncyCastleProvider());  // 프로바이더 추가 
	      
		Certification cerification = new Certification();
		
		
		KeyPair rootKeyPair = Certification.generateRSAKeyPair();  // 루트인증기관 키생성 및 인증서 발급
        X509Certificate rootCert = Certification.generateCertificate(
               new X500Principal("C=KR,CN=ROOT"), rootKeyPair.getPublic(),
               rootKeyPair.getPrivate(), null, CertType.ROOT);

        KeyPair interKeyPair = Certification.generateRSAKeyPair();  // 중간인증기관의 키생성 및 인증서 발급 
        X509Certificate interCert = Certification.generateCertificate(
               new X500Principal("C=KR,CN=INTER"), interKeyPair.getPublic(),
               rootKeyPair.getPrivate(), rootCert, CertType.INTER);
         
        KeyPair userKeyPair;
        X509Certificate userCert; //아래의 계정 생성에서 추가 
		/*******************************************************************************************************************/
		
		
		//통신 부분 
		while(true){	
			
			
			//클라이언트로 부터 메세지 받음 
			recvEncrptMsg=ReadFromClient.readLine();
			
			
			switch(Integer.parseInt(decryptMsg(recvEncrptMsg,key.priKey)))
			{
			case 1:
				String makeId=ReadFromClient.readLine();
				String makePasswd=ReadFromClient.readLine();
				String makeCertPasswd=ReadFromClient.readLine();
				
				String decryptId=decryptMsg(makeId, key.priKey);
				String decryptPasswd=decryptMsg(makePasswd, key.priKey);
				String decryptCertPasswd=decryptMsg(makeCertPasswd, key.priKey);
				
				if(makeAccount(decryptId,decryptPasswd))
				{
					WriteToClient.write("계정 생성 완료 ! "+"\n");
					WriteToClient.flush();
				
					 userKeyPair= Certification.generateRSAKeyPair();  
			         userCert = Certification.generateCertificate(
			               new X500Principal("C=KR,O=KUT,OU=IME,CN="+ decryptId), userKeyPair.getPublic(),
			               interKeyPair.getPrivate(), interCert, CertType.ENDENTITY);
			         
			         certSaveToFile(userCert,decryptId); //파일로 인증서 저장
			         
			         //인증서 개인키를 파일로 저장하기 위한 비밀키 저장
			         privKeySaveToFile(decryptCertPasswd,userCert,interCert,rootCert,userKeyPair,decryptId);
			         
			         System.out.println(userKeyPair.getPrivate());
				}
				else{
					WriteToClient.write("계정 생성 실패 !(이미 사용중인 아이디 입니다)"+"\n");
					WriteToClient.flush();
				}
				
				break;
			case 2: 
				String loginId=ReadFromClient.readLine();
				String loginPasswd=ReadFromClient.readLine();
				if(login(decryptMsg(loginId, key.priKey),decryptMsg(loginPasswd, key.priKey)))
				{
					WriteToClient.write("로그인 성공!"+"\n");
					WriteToClient.flush();
					flag=true;
				}else
				{
					WriteToClient.write("로그인 실패 !" + "\n");
					WriteToClient.flush();
					flag=false;
				}
				
				break;
			case 3:
				String certLoginId=ReadFromClient.readLine();
				String certLoginPasswd=ReadFromClient.readLine();
				String decryptCertLoginId=decryptMsg(certLoginId, key.priKey);
				String decryptCertLoginPasswd=decryptMsg(certLoginPasswd, key.priKey);
				
				if(!loadKeyFromFile(decryptCertLoginId,decryptCertLoginPasswd ,key))//파일이 없으면 즉, 등록된 사용자가 아니면
				{
					WriteToClient.write("등록된 사용자가 아닙니다." + "\n");
					WriteToClient.flush();
					flag=false;
				}else{
					System.out.println(key.restoreFromFileKey);
					if(verification(key.restoreFromFileKey,decryptCertLoginId))
					{
						WriteToClient.write("로그인 성공!" + "\n");
						WriteToClient.flush();	
						flag=true;
					}else{
						WriteToClient.write("로그인 실패!" + "\n");
						WriteToClient.flush();
						flag=false;
					}
				}
				
		         break;
		         
			case 4:
				if(flag=true)
				{
					while(true)
					{
						String recvCmd=ReadFromClient.readLine();
						
						Runtime clsRuntime = Runtime.getRuntime();
						
						try {
							Runtime oRuntime = Runtime.getRuntime();
							Process oProcess = oRuntime.exec("cmd /c "+decryptMsg(recvCmd, key.priKey));
						
						BufferedReader stdOut   = new BufferedReader(new InputStreamReader(oProcess.getInputStream()));
						String result;
						while((result=stdOut.readLine()) != null)
							WriteToClient.write(result+"\n");
							WriteToClient.flush();
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						WriteToClient.write("null" + "\n");
						WriteToClient.flush();
					}
				}else
				{
					WriteToClient.write("인증되지 않은 사용자 입니다 로그인 후 이용해 주십시오." + "\n");
					WriteToClient.flush();
					WriteToClient.write("null" + "\n");
					WriteToClient.flush();
				}
			case 5:
				socket.close();
				System.exit(0);
				
			}
			
			
		}

	}

	private static boolean verification(PrivateKey userPrivKey,String certId) throws UnsupportedEncodingException, NoSuchAlgorithmException, FileNotFoundException, InvalidKeyException, SignatureException, CertificateException {
		// TODO Auto-generated method stub
		
	        // 6.1 RSA 서명  (Alice의 개인키 이용)    
	     String sigData="전자서명 테스트";
	     byte[] data = sigData.getBytes("UTF8");
	              
	     Signature sig = Signature.getInstance("MD5WithRSA");
	     FileInputStream fis = new FileInputStream(new File(certId+"Priv.key"));
	     
	     sig.initSign(userPrivKey);
	     sig.update(data);
	     byte[] signatureBytes = sig.sign();
	     // 6.2 RSA 서명 검증  (Alice의 인증서에 있는 공개키 이용)    
	     CertificateFactory cf1 = CertificateFactory.getInstance("X.509");
	     FileInputStream fis1 = new FileInputStream(new File(certId+"Cert.der"));
	     X509Certificate cert1 = (X509Certificate)cf1.generateCertificate(fis1);  // 파일에서 읽어서 인증서 형식으로 할당 
	     
	     sig.initVerify(cert1.getPublicKey());
	     sig.update(data);
	     
	     return sig.verify(signatureBytes);
	     
	}

	private static boolean loadKeyFromFile(String certLoginId, String certLoginPasswd, Key key) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		// TODO Auto-generated method stub
		
		File file = new File(certLoginId +"Priv.key");
		
		if(file.exists())
		{
	        FileInputStream fileInputStream = new FileInputStream(file);
	        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
	       try {
	        	ks.load(fileInputStream,certLoginPasswd.toCharArray());  // 파일에서 읽어와서 키스토어에 로드 	
			} catch (Exception e) {
				// TODO: handle exception
		        	return false;
		        
			}
	        fileInputStream.close();
	        key.restoreFromFileKey= (PrivateKey)ks.getKey(certLoginId + "PrivateKeyAlias",certLoginPasswd.toCharArray()); // 키스토어에서 개인키를 읽어올때 암호화 키 코드 필요 
	        
	        return true;
	        
		}else
			return false;
		
	}

	private static void privKeySaveToFile(String decryptCertPasswd, X509Certificate userCert, X509Certificate interCert,
			X509Certificate rootCert, KeyPair userKeyPair, String decryptId) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		// TODO Auto-generated method stub
		 char[] code = decryptCertPasswd.toCharArray();
         KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());  // 키스토어라는 형태로 저장하게 됨 
         keyStore.load(null,null);
         
         X509Certificate[] chain = new X509Certificate[3];  // 키스토어에 저장시 인증체인 정보 필요. 루트로부터 사용자까지의 인증서 정보  
         chain[0] = userCert;  // 사용자 인증서 
         chain[1] = interCert;  // 중간인증기관 인증서 (중간인증기관이 Alice에게 인증서를 발급) 
         chain[2] = rootCert;  // 루트인증기관 인증서 (루트인증기관이 중간인증기관에게 인증서를 발급) 
         keyStore.setKeyEntry(decryptId + "PrivateKeyAlias",userKeyPair.getPrivate(),code,chain); // 필요한 정보를 키스토어에 암호화하여 저장 
         FileOutputStream fileOutputStream = new FileOutputStream(new File(decryptId+"Priv.key"));   
         keyStore.store(fileOutputStream,code);  // 키스토어의 내용을 code로 암호화하여 파일로 저장 
         fileOutputStream.close();
        
		
	}

	private static void certSaveToFile(X509Certificate userCert, String decryptId) throws CertificateEncodingException, IOException {
		// TODO Auto-generated method stub
        FileOutputStream outputStream = new FileOutputStream(new File(decryptId+"Cert.der")); 
        outputStream.write(userCert.getEncoded());  // 파일로 저장 
        outputStream.close();

		
	}

	private static String decryptMsg(String recvEncrptMsg,PrivateKey privateKey) throws GeneralSecurityException {
		// TODO Auto-generated method stub
		//Base64 디코딩
		Decoder decoder = Base64.getDecoder();
		byte[] decodeBytes = decoder.decode(recvEncrptMsg);
		System.out.println("암호화 문장 : " + bytesToHex(decodeBytes));
		byte[] decrpMsg=decrypt(privateKey,decodeBytes);
		String recvPlainText=new String(decrpMsg);
		System.out.println("Recv Msg : " + recvPlainText);
		return recvPlainText;
		
	}

	private static boolean login(String loginId, String loginPasswd) throws IOException {
		// TODO Auto-generated method stub
		File accountFile = new File(loginId+".Account");
		if(accountFile.exists()) 
		{
			BufferedReader inputFile = new BufferedReader(new FileReader(accountFile));
			inputFile.readLine(); //skip ID
			String readPasswd=inputFile.readLine();
			if(loginPasswd.equals(readPasswd))
				return true;
			
			return false;
			
		}else
			return false;
		
	}

	private static boolean makeAccount(String Id,String Passwd) throws IOException {

		File accountFile = new File(Id+".Account");
		if(!accountFile.exists()) //파일이 없으면 생성 후 true 반환
		{
			BufferedWriter outputFile = new BufferedWriter(new PrintWriter(accountFile));
	
			outputFile.write(Id+"\n");
			outputFile.write(Passwd+"\n");
			outputFile.flush();
			outputFile.close(); // 파일을 닫음.
			
			return true;
		}else //있으면 false반환
		{
			return false;
		}

	}
}
