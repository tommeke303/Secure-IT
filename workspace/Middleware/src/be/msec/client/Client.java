package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;
import be.msec.government.client.GVMTimestampClient;
import be.msec.serviceProvider.SPmessage;
import be.msec.serviceProvider.client.SPClient;
import javafx.util.Pair;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.nio.file.Paths;
import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.smartcardio.*;
import javax.sql.rowset.serial.SerialBlob;

import com.sun.org.apache.xml.internal.serializer.SerializerBase;
import com.sun.xml.internal.bind.v2.runtime.unmarshaller.XsiNilLoader.Array;
import com.sun.xml.internal.ws.util.Pool.TubePool;

public class Client {

	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		IConnection c;
		boolean simulation = true; // Choose simulation vs real card here

		/*
		 * // random byte? SecureRandom random =
		 * SecureRandom.getInstance("SHA1PRNG"); byte[] bytes = new byte [20];
		 * random.nextBytes(bytes) ;
		 */

		if (simulation) {
			// Simulation:
			c = new SimulatedConnection();
		} else {
			// Real Card:
			c = new Connection();
			((Connection) c).setTerminal(0); // depending on which cardreader
												// you use
		}

		c.connect();

		try {

			/*
			 * For more info on the use of CommandAPDU and ResponseAPDU: See
			 * http://java.sun.com/javase/6/docs/jre/api/security/smartcardio/
			 * spec/index.html
			 */

			CommandAPDU a;
			ResponseAPDU r;

			if (simulation) {
				// 0. create applet (only for simulator!!!)
				a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
						new byte[] { (byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01 }, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW() != 0x9000)
					throw new Exception("select installer applet failed");

				a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,
						new byte[] { 0xb, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00 },
						0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW() != 0x9000)
					throw new Exception("Applet creation failed");

				// 1. Select applet (not required on a real card, applet is
				// selected by default)
				a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
						new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00 }, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW() != 0x9000)
					throw new Exception("Applet selection failed");
			}

			// 2. Send PIN
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, new byte[] { 0x01, 0x02, 0x03, 0x04 });
			r = c.transmit(a);

			System.out.println(r);
			if (r.getSW() == SW_VERIFICATION_FAILED)
				throw new Exception("PIN INVALID");
			else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());
			System.out.println("PIN Verified");

			/**
			 * --------------------------------------end original
			 * code-------------------------------------------------------------------
			 */

			/**
			 * STEP 1: update time, TODO on javacard: (3)
			 */
			// TODO: (2): send "hello" + current time to card
			Timestamp timestamp = new Timestamp(System.currentTimeMillis());

			// TODO: (4): receive 'reqValidation' from card
			// tijdelijke responce
			Boolean reqRevalidation = true;

			// (5), set new time when revalidation is required
			if (reqRevalidation) {
				// (6)->(9)
				byte[] encryptedTimestamp = new GVMTimestampClient().getTimestampRaw();

				// TODO: (9)->(12)
			}

			/**
			 * STEP 2: authenticate Service Provider
			 */
			SPClient service = new SPClient();

			// TODO (1) send this certificate to the javacard 
			X509Certificate cert = service.getServiceCertificate();

			/**
			 * TODO stuff to do on javacard
			 * (2)-(8)
			 */

			 // verify certificate
			// cert.verify(*CA pk*); // (2)
			cert.checkValidity(timestamp); // (3), use lastValidationTime instead of timestamp
			 
			// (4) make symmetric key
			String algSym = "AES";
			Cipher cph = Cipher.getInstance(algSym);
			Key symKey = KeyGenerator.getInstance("AES").generateKey();

			// (5) encrypt symKey with pk of cert
			String algAsym = "RSA/ECB/PKCS1Padding";
			PublicKey pk = cert.getPublicKey();
			cph = Cipher.getInstance(algAsym);
			System.out.println("alg: " + pk.getAlgorithm());
			cph.init(Cipher.ENCRYPT_MODE, pk);
			byte[] encryptedSymKey = cph.doFinal(symKey.getEncoded());

			// (6) generate random nr
			Random rand = new Random();
			int n = rand.nextInt();
			System.out.println("Random: " + n);

			// (7)
			Pair<Integer, X509Certificate> msg = new Pair<Integer, X509Certificate>(n, cert);
			
			cph = Cipher.getInstance(algSym);
			cph.init(Cipher.ENCRYPT_MODE, symKey);
			byte[] encryptedMsg = cph.doFinal(convertToBytes(msg));

			/**
			// conversion tests (working)
			Pair<Integer, X509Certificate> test = (Pair<Integer, X509Certificate>) convertToObject(convertToBytes(msg));
			System.out.println("Original: " + msg.toString());
			System.out.println("Converted twice: " + test.toString());
			*/

			// TODO (8) send encryptedMsg & encryptedSymKey to middelware
			
			// just to keep client running
			while (true) {

			}

		} catch (Exception e) {
			throw e;
		} finally {
			c.close(); // close the connection with the card
		}
	}

	// search for an attribute
	public static String getCertificateServiceName(X509Certificate cert) {
		return getCertificateAttribute(cert, "CN");
	}

	public static String getCertificateDomain(X509Certificate cert) {
		return getCertificateAttribute(cert, "DC");
	}

	public static String getCertificateAttribute(X509Certificate cert, String Attribute) {
		String input = cert.getSubjectDN().toString();
		String output = "";

		// loop through all attributes
		for (String attr : input.split(", ")) {
			String[] details = attr.split("=");
			String attrName = details[0];
			String attrValue = details[1];

			// if correct attribute, set output & stop
			if (attrName.toLowerCase().equals(Attribute.toLowerCase())) {
				output = attrValue;
				break;
			}
		}

		return output;
	}

	public static byte[] convertToBytes(Object input) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput out = null;
		try {
			out = new ObjectOutputStream(bos);
			out.writeObject(input);
			out.flush();
			byte[] yourBytes = bos.toByteArray();

			bos.close();

			return yourBytes;
		} catch (Exception ex) {
			return null;
		}
	}

	public static Object convertToObject(byte[] yourBytes) {
		ByteArrayInputStream bis = new ByteArrayInputStream(yourBytes);
		ObjectInput in = null;
		try {
			in = new ObjectInputStream(bis);
			Object o = in.readObject();

			in.close();

			return o;
		} catch (Exception ex) {
			// ignore close exception

			return null;
		}
	}
}
