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

        
        System.out.println("=== RSA Ű���� ===");
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
		//Ű���� ������ �ִ� class ����
		Key key = new Key();
		MakeRSAKey(key); //Ű ����
		
		System.out.println(" ����Ű : "+bytesToHex(key.publicKey));
		
		//��Ʈ ����
		ServerSocket serverSocket = new ServerSocket(8013);

		
		System.out.println("Listening...");
		Socket socket = serverSocket.accept();
		System.out.println("Client("+socket.getInetAddress()+") Connect!");
		
		//��� ��Ʈ�� ����
		OutputStream OutputClient = socket.getOutputStream();
		BufferedWriter WriteToClient = new BufferedWriter(new OutputStreamWriter(OutputClient));
		
		//�Է� ��Ʈ�� ����
		InputStream InputClient = socket.getInputStream();
		BufferedReader ReadFromClient = new BufferedReader(new InputStreamReader(InputClient));
	
	
		//������ ���� ����Ű�� Base64Ÿ������ ���ڵ�
		Encoder encoder = Base64.getEncoder();
		String publicKey = encoder.encodeToString(key.publicKey);

		
		//����Ű ����
		WriteToClient.write(publicKey+"\n");
		WriteToClient.flush();
		
		String recvEncrptMsg=null;
	
		/********************************************������ ���� �ҽ� �ڵ� ********************************************************/
	      // BouncyCastle Provider �߰�
	    Security.addProvider(new BouncyCastleProvider());  // ���ι��̴� �߰� 
	      
		Certification cerification = new Certification();
		
		
		KeyPair rootKeyPair = Certification.generateRSAKeyPair();  // ��Ʈ������� Ű���� �� ������ �߱�
        X509Certificate rootCert = Certification.generateCertificate(
               new X500Principal("C=KR,CN=ROOT"), rootKeyPair.getPublic(),
               rootKeyPair.getPrivate(), null, CertType.ROOT);

        KeyPair interKeyPair = Certification.generateRSAKeyPair();  // �߰���������� Ű���� �� ������ �߱� 
        X509Certificate interCert = Certification.generateCertificate(
               new X500Principal("C=KR,CN=INTER"), interKeyPair.getPublic(),
               rootKeyPair.getPrivate(), rootCert, CertType.INTER);
         
        KeyPair userKeyPair;
        X509Certificate userCert; //�Ʒ��� ���� �������� �߰� 
		/*******************************************************************************************************************/
		
		
		//��� �κ� 
		while(true){	
			
			
			//Ŭ���̾�Ʈ�� ���� �޼��� ���� 
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
					WriteToClient.write("���� ���� �Ϸ� ! "+"\n");
					WriteToClient.flush();
				
					 userKeyPair= Certification.generateRSAKeyPair();  
			         userCert = Certification.generateCertificate(
			               new X500Principal("C=KR,O=KUT,OU=IME,CN="+ decryptId), userKeyPair.getPublic(),
			               interKeyPair.getPrivate(), interCert, CertType.ENDENTITY);
			         
			         certSaveToFile(userCert,decryptId); //���Ϸ� ������ ����
			         
			         //������ ����Ű�� ���Ϸ� �����ϱ� ���� ���Ű ����
			         privKeySaveToFile(decryptCertPasswd,userCert,interCert,rootCert,userKeyPair,decryptId);
			         
			         System.out.println(userKeyPair.getPrivate());
				}
				else{
					WriteToClient.write("���� ���� ���� !(�̹� ������� ���̵� �Դϴ�)"+"\n");
					WriteToClient.flush();
				}
				
				break;
			case 2: 
				String loginId=ReadFromClient.readLine();
				String loginPasswd=ReadFromClient.readLine();
				if(login(decryptMsg(loginId, key.priKey),decryptMsg(loginPasswd, key.priKey)))
				{
					WriteToClient.write("�α��� ����!"+"\n");
					WriteToClient.flush();
					flag=true;
				}else
				{
					WriteToClient.write("�α��� ���� !" + "\n");
					WriteToClient.flush();
					flag=false;
				}
				
				break;
			case 3:
				String certLoginId=ReadFromClient.readLine();
				String certLoginPasswd=ReadFromClient.readLine();
				String decryptCertLoginId=decryptMsg(certLoginId, key.priKey);
				String decryptCertLoginPasswd=decryptMsg(certLoginPasswd, key.priKey);
				
				if(!loadKeyFromFile(decryptCertLoginId,decryptCertLoginPasswd ,key))//������ ������ ��, ��ϵ� ����ڰ� �ƴϸ�
				{
					WriteToClient.write("��ϵ� ����ڰ� �ƴմϴ�." + "\n");
					WriteToClient.flush();
					flag=false;
				}else{
					System.out.println(key.restoreFromFileKey);
					if(verification(key.restoreFromFileKey,decryptCertLoginId))
					{
						WriteToClient.write("�α��� ����!" + "\n");
						WriteToClient.flush();	
						flag=true;
					}else{
						WriteToClient.write("�α��� ����!" + "\n");
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
					WriteToClient.write("�������� ���� ����� �Դϴ� �α��� �� �̿��� �ֽʽÿ�." + "\n");
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
		
	        // 6.1 RSA ����  (Alice�� ����Ű �̿�)    
	     String sigData="���ڼ��� �׽�Ʈ";
	     byte[] data = sigData.getBytes("UTF8");
	              
	     Signature sig = Signature.getInstance("MD5WithRSA");
	     FileInputStream fis = new FileInputStream(new File(certId+"Priv.key"));
	     
	     sig.initSign(userPrivKey);
	     sig.update(data);
	     byte[] signatureBytes = sig.sign();
	     // 6.2 RSA ���� ����  (Alice�� �������� �ִ� ����Ű �̿�)    
	     CertificateFactory cf1 = CertificateFactory.getInstance("X.509");
	     FileInputStream fis1 = new FileInputStream(new File(certId+"Cert.der"));
	     X509Certificate cert1 = (X509Certificate)cf1.generateCertificate(fis1);  // ���Ͽ��� �о ������ �������� �Ҵ� 
	     
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
	        	ks.load(fileInputStream,certLoginPasswd.toCharArray());  // ���Ͽ��� �о�ͼ� Ű���� �ε� 	
			} catch (Exception e) {
				// TODO: handle exception
		        	return false;
		        
			}
	        fileInputStream.close();
	        key.restoreFromFileKey= (PrivateKey)ks.getKey(certLoginId + "PrivateKeyAlias",certLoginPasswd.toCharArray()); // Ű������ ����Ű�� �о�ö� ��ȣȭ Ű �ڵ� �ʿ� 
	        
	        return true;
	        
		}else
			return false;
		
	}

	private static void privKeySaveToFile(String decryptCertPasswd, X509Certificate userCert, X509Certificate interCert,
			X509Certificate rootCert, KeyPair userKeyPair, String decryptId) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		// TODO Auto-generated method stub
		 char[] code = decryptCertPasswd.toCharArray();
         KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());  // Ű������� ���·� �����ϰ� �� 
         keyStore.load(null,null);
         
         X509Certificate[] chain = new X509Certificate[3];  // Ű���� ����� ����ü�� ���� �ʿ�. ��Ʈ�κ��� ����ڱ����� ������ ����  
         chain[0] = userCert;  // ����� ������ 
         chain[1] = interCert;  // �߰�������� ������ (�߰���������� Alice���� �������� �߱�) 
         chain[2] = rootCert;  // ��Ʈ������� ������ (��Ʈ��������� �߰������������ �������� �߱�) 
         keyStore.setKeyEntry(decryptId + "PrivateKeyAlias",userKeyPair.getPrivate(),code,chain); // �ʿ��� ������ Ű���� ��ȣȭ�Ͽ� ���� 
         FileOutputStream fileOutputStream = new FileOutputStream(new File(decryptId+"Priv.key"));   
         keyStore.store(fileOutputStream,code);  // Ű������� ������ code�� ��ȣȭ�Ͽ� ���Ϸ� ���� 
         fileOutputStream.close();
        
		
	}

	private static void certSaveToFile(X509Certificate userCert, String decryptId) throws CertificateEncodingException, IOException {
		// TODO Auto-generated method stub
        FileOutputStream outputStream = new FileOutputStream(new File(decryptId+"Cert.der")); 
        outputStream.write(userCert.getEncoded());  // ���Ϸ� ���� 
        outputStream.close();

		
	}

	private static String decryptMsg(String recvEncrptMsg,PrivateKey privateKey) throws GeneralSecurityException {
		// TODO Auto-generated method stub
		//Base64 ���ڵ�
		Decoder decoder = Base64.getDecoder();
		byte[] decodeBytes = decoder.decode(recvEncrptMsg);
		System.out.println("��ȣȭ ���� : " + bytesToHex(decodeBytes));
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
		if(!accountFile.exists()) //������ ������ ���� �� true ��ȯ
		{
			BufferedWriter outputFile = new BufferedWriter(new PrintWriter(accountFile));
	
			outputFile.write(Id+"\n");
			outputFile.write(Passwd+"\n");
			outputFile.flush();
			outputFile.close(); // ������ ����.
			
			return true;
		}else //������ false��ȯ
		{
			return false;
		}

	}
}
