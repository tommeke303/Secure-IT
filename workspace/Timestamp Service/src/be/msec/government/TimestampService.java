package be.msec.government;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.crypto.*;
import java.security.cert.Certificate;
import java.sql.Timestamp;

public class TimestampService {

	public static void main(String[] args) throws Exception {
		int ssPort = 443;
		
		SSLServerSocketFactory factory =  (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		SSLServerSocket ssocket = (SSLServerSocket) factory.createServerSocket(ssPort);

		System.out.println("Working Directory = " +
	              System.getProperty("user.dir"));
		
		 String certificatePath = Paths.get(System.getProperty("user.dir")).getParent().toString() + File.separator + "Certificates" + File.separator; 
		
		while (true) {
		    
		    // get certificate
            KeyStore keyStore = KeyStore.getInstance("JKS");
            String fileName = certificatePath + "government.jks";
            FileInputStream fis = new FileInputStream(fileName);
            keyStore.load(fis, "password".toCharArray());
            fis.close();

            PrivateKey pr = (PrivateKey) keyStore.getKey("government", "".toCharArray());
            PublicKey pk = keyStore.getCertificate("government").getPublicKey();

            String alg = "RSA";
            Cipher c;
            
            Timestamp timestamp = new Timestamp(System.currentTimeMillis());
            System.out.println("\nOriginal timestamp: \n" + timestamp);
         

            // encrypt
            c = Cipher.getInstance(alg);
            c.init(Cipher.ENCRYPT_MODE, pr);
            byte[] encrypted = c.doFinal((timestamp.getTime() + "").getBytes());
            System.out.println("\nEncrypted text: \n" + new String(encrypted));
            
         // decrypt
            c = Cipher.getInstance(alg);
            c.init(Cipher.DECRYPT_MODE, pk);
            byte[] decrypted = c.doFinal(encrypted);
            long givenTime = Long.parseLong(new String(decrypted));
            
            System.out.println("\nDecrypted text: \n" + new String(decrypted));
            System.out.println("\nDecrypted time: \n" + new Timestamp(givenTime));
            

			// accept new connection
			Socket socket = ssocket.accept();
			InputStream in = socket.getInputStream();
		    OutputStream out = socket.getOutputStream();
		    
		    // close connection
		    in.close();
		    out.close();
		}
	}

}