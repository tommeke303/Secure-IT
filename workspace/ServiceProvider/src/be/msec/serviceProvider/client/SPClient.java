package be.msec.serviceProvider.client;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import be.msec.serviceProvider.SPmessage;

public class SPClient {
	// network address
	private String Address = "localhost";
	private int Port = 1251;

	// find keystore
	private String keyStorePath = Paths.get(System.getProperty("user.dir")).getParent().toString() + File.separator
			+ "Certificates" + File.separator;
	private String ClientKeyStore = keyStorePath + "common.jks";
	private String ClientKeyPassword = "password";
	private String CertificateName = "serviceprovider (ca)";
	
	private ObjectOutputStream out;
	private ObjectInputStream in;
	private X509Certificate cert;
	
	public SPClient() throws Exception {
		// initialize connection
		SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		SSLSocket socket = (SSLSocket) factory.createSocket(Address, Port);
		out = new ObjectOutputStream(socket.getOutputStream());
		in = new ObjectInputStream(socket.getInputStream());
		
		System.out.println("Connected to service provider");

		// get service data when available
		SPmessage msg = (SPmessage) in.readObject();
		cert = (X509Certificate) msg.getData();
		
		System.out.println("certificate gotten");
		System.out.println("subj DN: " + cert.getSubjectDN());
		System.out.println("Princ. name: " + cert.getSubjectDN().getName());
	}
	
	public X509Certificate getServiceCertificate(){
		return this.cert;
	}
}