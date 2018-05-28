package be.msec.government;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.crypto.*;
import java.sql.Timestamp;
import com.sun.net.ssl.internal.ssl.*;;

public class GVMMain {

	public static void main(String[] args) throws Exception {
		int ssPort = 1250;

		// find keystore
		String keyStorePath = Paths.get(System.getProperty("user.dir")).getParent().toString() + File.separator
				+ "Certificates" + File.separator;
		String governmentKeyStore = keyStorePath + "government.jks";
		String governmentKeyPassword = "password";
		String CertificateName = "government";

		// check out path
		// System.out.println("Working Directory = " +
		// System.getProperty("user.dir"));

		// set security properties
		Security.addProvider(new Provider());
		System.setProperty("javax.net.ssl.keyStore", governmentKeyStore);
		System.setProperty("javax.net.ssl.keyStorePassword", governmentKeyPassword);

		// optional: show details about handshake
		// System.setProperty("javax.net.debug", "all");

		// make ssl server socket
		SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		SSLServerSocket ssocket = (SSLServerSocket) factory.createServerSocket(ssPort);

		// get certificate
		KeyStore keyStore = KeyStore.getInstance("JKS");
		FileInputStream fis = new FileInputStream(governmentKeyStore);
		keyStore.load(fis, governmentKeyPassword.toCharArray());
		fis.close();

		// get key
		PrivateKey pr = (PrivateKey) keyStore.getKey(CertificateName, governmentKeyPassword.toCharArray());

		// algorithm
		String alg = "RSA/ECB/PKCS1Padding";
		Cipher c;

		// feedback
		System.out.println("Timestamp service started and ready for accepting connections");

		while (true) {
			// accept new connection
			Socket socket = ssocket.accept();
			ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
			System.out.println("\nNew connection accepted");
 
			Timestamp timestamp = new Timestamp(System.currentTimeMillis());
			System.out.println("Original timestamp: " + timestamp);

			// encrypt
			c = Cipher.getInstance(alg);
			c.init(Cipher.ENCRYPT_MODE, pr);
			byte[] encrypted = c.doFinal((timestamp.getTime() + "").getBytes());

			// send encrypted data
			out.writeObject(encrypted);
			System.out.println("Timestamp sent");

			out.close();
			System.out.println("Connection closed");
		}

	}
}
