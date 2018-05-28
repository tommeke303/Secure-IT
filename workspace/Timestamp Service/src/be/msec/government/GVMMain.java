package be.msec.government;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.sql.Timestamp;
import com.sun.net.ssl.internal.ssl.*;

import be.msec.serviceProvider.tools.SPtools;
import javafx.util.Pair;;

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

		// feedback
		System.out.println("Timestamp service started and ready for accepting connections");

		while (true) {
			// accept new connection
			Socket socket = ssocket.accept();
			ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
			System.out.println("\nNew connection accepted");
 
			// (7)
			Timestamp timestamp = new Timestamp(System.currentTimeMillis());
			System.out.println("Original timestamp: " + timestamp);
			
			// (8)
			// make signature
			byte[] data = SPtools.convertToBytes(timestamp);
	        Signature sig = Signature.getInstance("SHA1WithRSA");
	        sig.initSign(pr);
	        sig.update(data);
	        byte[] signatureBytes = sig.sign();

	        Pair<byte[], Timestamp> toSend = new Pair<byte[], Timestamp>(signatureBytes, timestamp);
	        
			// send encrypted data
			out.writeObject(toSend);
			System.out.println("Timestamp sent");

			out.close();
			System.out.println("Connection closed");
		}

	}
}
