package be.msec.government;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.sun.net.ssl.internal.ssl.Provider;

public class TimestampClientTest {

	public static void main(String[] args) throws Exception {
		String governmentAddress = "localhost";
		int governmentPort = 443;

		// find keystore
		String keyStorePath = Paths.get(System.getProperty("user.dir")).getParent().toString() + File.separator
				+ "Certificates" + File.separator;
		String ClientKeyStore = keyStorePath + "client.jks";
		String ClientKeyPassword = "password";

		// set security properties
		Security.addProvider(new Provider());
		System.setProperty("javax.net.ssl.trustStore", ClientKeyStore);
		System.setProperty("javax.net.ssl.trustStorePassword", ClientKeyPassword);

		// optional: show details about handshake
		// System.setProperty("javax.net.debug", "all");

		SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		SSLSocket socket = (SSLSocket) factory.createSocket(governmentAddress, governmentPort);

		DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));

		// get data
		ArrayList<Byte> inputList = new ArrayList<Byte>();
		int count;
		byte[] Buffer = new byte[32];
		while ((count = in.read(Buffer)) > 0) {
			byte[] found = Arrays.copyOfRange(Buffer, 0, count);
			for (byte b : found) {
				inputList.add(b);
			}
		}

		// convert from Byte[] to byte[]
		byte[] Result = new byte[inputList.size()];
		for (int i = 0; i < inputList.size(); i++) {
			Result[i] = inputList.get(i);
		}

		// close connections
		in.close();

		// get certificate
		KeyStore keyStore = KeyStore.getInstance("JKS");
		// FileInputStream fis = new FileInputStream(ClientKeyStore);
		FileInputStream fis = new FileInputStream(keyStorePath + "government.jks");
		keyStore.load(fis, ClientKeyPassword.toCharArray());
		fis.close();

		PrivateKey pr = (PrivateKey) keyStore.getKey("government", ClientKeyPassword.toCharArray());
		PublicKey pk = keyStore.getCertificate("government").getPublicKey();

		String alg = "RSA/ECB/PKCS1Padding";
		Cipher c;

		// decrypt
		c = Cipher.getInstance(alg);
		c.init(Cipher.DECRYPT_MODE, pk);
		byte[] decrypted = c.doFinal(Result);
		String asString = new String(decrypted);
		Timestamp theTime = new Timestamp(new Long(asString));

		System.out.println("Timestamp gotten from government:");
		System.out.println(theTime);
	}

}