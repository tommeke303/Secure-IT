package be.msec.serviceProvider.client;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SPClient {
	// network address
	private String Address = "localhost";
	private int Port = 444;

	// find keystore
	private String keyStorePath = Paths.get(System.getProperty("user.dir")).getParent().toString() + File.separator
			+ "Certificates" + File.separator;
	private String ClientKeyStore = keyStorePath + "common.jks";
	private String ClientKeyPassword = "password";
	private String CertificateName = "serviceprovider (ca)";

	// query requests
	private int REQclose = 0;
	private int REQserviceCertificate = 1;
	
	private OutputStream out;
	private DataInputStream in;
	private X509Certificate cert;
	
	public SPClient() throws Exception {
		// initialize connection
		SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		SSLSocket socket = (SSLSocket) factory.createSocket(Address, Port);
		out = socket.getOutputStream();
		in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
		
		System.out.println("Connected to service provider");

		// get service data when available
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(sendQuery(REQserviceCertificate));
		cert = (X509Certificate) certFactory.generateCertificate(in);
	}

	private byte[] sendQuery(int request) throws Exception {
		// send data
		out.write(request);
		System.out.println("send request");
		
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
		return Result;
	}
}
