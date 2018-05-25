package be.msec.government.client;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.sun.net.ssl.internal.ssl.Provider;

public class GVMTimestampClient {
	// network address
	private String Address = "localhost";
	private int Port = 1250;

	// find keystore
	private String keyStorePath = Paths.get(System.getProperty("user.dir")).getParent().toString() + File.separator
			+ "Certificates" + File.separator;
	private String ClientKeyStore = keyStorePath + "common.jks";
	private String ClientKeyPassword = "password";
	private String CertificateName = "government (ca)";
	
	/**
	 * Ask the government for a timestamp and have it already decrypted.
	 * 
	 * @return The timestamp from the government, already decrypted for you.
	 * @throws Exception If something went wrong.
	 */
	public Timestamp getTimestampDecrypted() throws Exception {
		byte[] Raw = getTimestampRaw();

		// get certificate
		KeyStore keyStore = KeyStore.getInstance("JKS");
		FileInputStream fis = new FileInputStream(ClientKeyStore);
		keyStore.load(fis, ClientKeyPassword.toCharArray());
		fis.close();

		PrivateKey pr = (PrivateKey) keyStore.getKey("government", ClientKeyPassword.toCharArray());
		PublicKey pk = keyStore.getCertificate(CertificateName).getPublicKey();
		
		/*
		X509Certificate a = (X509Certificate) keyStore.getCertificate(CertificateName);
		System.out.println("domain: " + a.getSubjectDN());
		*/
		
		// verify
		keyStore.getCertificate(CertificateName).verify(keyStore.getCertificate("ca").getPublicKey());
		
		String alg = "RSA/ECB/PKCS1Padding";
		Cipher c;

		// decrypt
		c = Cipher.getInstance(alg);
		c.init(Cipher.DECRYPT_MODE, pk);
		byte[] decrypted = c.doFinal(Raw);
		String asString = new String(decrypted);
		Timestamp theTime = new Timestamp(new Long(asString));

		return theTime;
	}

	/**
	 * Ask the government for a timestamp.
	 * 
	 * @return The timestamp from the government, encrypted with the private key of the government
	 * @throws Exception If something went wrong.
	 */
	public byte[] getTimestampRaw() throws Exception {
		// set security properties
		Security.addProvider(new Provider());
		System.setProperty("javax.net.ssl.trustStore", ClientKeyStore);
		System.setProperty("javax.net.ssl.trustStorePassword", ClientKeyPassword);

		// optional: show details about handshake
		// System.setProperty("javax.net.debug", "all");

		SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		SSLSocket socket = (SSLSocket) factory.createSocket(Address, Port);

		// OLD
		ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
		byte[] result = (byte[]) in.readObject();
		
		// close connections
		in.close();
		
		return result;
	}
}
