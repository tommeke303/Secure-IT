package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;
import be.msec.government.client.GVMTimestampClient;
import be.msec.serviceProvider.SPdomain;
import be.msec.serviceProvider.SPmessage;
import be.msec.serviceProvider.SPmessageType;
import be.msec.serviceProvider.client.SPClient;
import be.msec.serviceProvider.tools.SPtools;
import javafx.util.Pair;
import sun.misc.Resource;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.smartcardio.*;
import javax.swing.ImageIcon;

public class Client {

	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private static String algSym;
	private static Cipher cph;
	private static SecretKey symKey;

	/**
	 * @param args
	 */
	@SuppressWarnings("resource")
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

			// TODO: (3) todo on javacard
			// 1sec, 1min, 1hour, 1 day, a week
			long threshold = 1000 * 60 * 60 * 24 * 7; // example threshold
			Timestamp lastValidationTime = new Timestamp(0); // make serious out
																// of date
																// timestamp
																// (for testing
																// purpose)
			Boolean reqRevalidation = lastValidationTime.getTime() < (timestamp.getTime() - threshold);

			// TODO: (4): receive 'reqValidation' from card

			// (5), set new time when revalidation is required
			if (reqRevalidation) {
				// (6)->(9)
				Pair<byte[], Timestamp> encryptedTimestamp = new GVMTimestampClient().getTimestampRaw();

				// TODO: (9)->(12) in javacard

				// get public key, dees is enkel voor in de client.java, normaal
				// heeft de javacard de public key van government al opgeslagen
				String keyStorePath = Paths.get(System.getProperty("user.dir")).getParent().toString() + File.separator
						+ "Certificates" + File.separator;
				String ClientKeyStore = keyStorePath + "common.jks";
				String ClientKeyPassword = "password";
				String CertificateName = "government (ca)";
				KeyStore keyStore = KeyStore.getInstance("JKS");
				FileInputStream fis = new FileInputStream(ClientKeyStore);
				keyStore.load(fis, ClientKeyPassword.toCharArray());
				fis.close();
				PublicKey pk = keyStore.getCertificate(CertificateName).getPublicKey();

				// (10) verify timestamp
				Signature sig = Signature.getInstance("SHA1WithRSA");
				sig.initVerify(pk);
				sig.update(SPtools.convertToBytes(encryptedTimestamp.getValue()));
				if (!sig.verify(encryptedTimestamp.getKey()))
					throw new Exception("Government signature was invalid!");

				// (11) check if new time is actually new
				if (lastValidationTime.getTime() >= encryptedTimestamp.getValue().getTime())
					throw new Exception("New time is smaller (or equal) to old time, something went wrong!");

				// (12) set new time in memory
				lastValidationTime = encryptedTimestamp.getValue();
			}

			/**
			 * STEP 2: authenticate Service Provider
			 */
			System.out.println("Making connection to SP.");
			SPClient service = new SPClient();

			// TODO (1) send this certificate to the javacard
			X509Certificate cert_SP = service.getServiceCertificate();
			System.out.println("Connected to SP and certificate received, forwarding to javacard.");

			/**
			 * TODO stuff to do on javacard (2)-(8)
			 * --------------------------------------------
			 */

			// verify certificate
			// cert.verify(*CA pk*); // (2)
			cert_SP.checkValidity(timestamp); // (3), use lastValidationTime
											// instead of timestamp

			// (4) make symmetric key
			algSym = "AES";
			cph = Cipher.getInstance(algSym);
			symKey = KeyGenerator.getInstance("AES").generateKey();

			// (5) encrypt symKey with pk of cert
			String algAsym = "RSA/ECB/PKCS1Padding";
			PublicKey pk = cert_SP.getPublicKey();
			cph = Cipher.getInstance(algAsym);
			cph.init(Cipher.ENCRYPT_MODE, pk);
			byte[] encryptedSymKey = cph.doFinal(symKey.getEncoded());

			// (6) generate random nr
			Random rand = new Random();
			int n = rand.nextInt();

			// (7) encrypt challenge with symmetric key
			Pair<Integer, String> msg = new Pair<Integer, String>(n, cert_SP.getSubjectDN().getName());
			cph = Cipher.getInstance(algSym);
			cph.init(Cipher.ENCRYPT_MODE, symKey);
			byte[] encryptedMsg = cph.doFinal(SPtools.convertToBytes(msg));

			/**
			 * // conversion tests (working) Pair<Integer, X509Certificate> test
			 * = (Pair<Integer, X509Certificate>)
			 * convertToObject(convertToBytes(msg));
			 * System.out.println("Original: " + msg.toString());
			 * System.out.println("Converted twice: " + test.toString());
			 */

			// TODO (8).1 send encryptedMsg & encryptedSymKey to middelware
			/**
			 * --------------------------------------------------
			 */
			System.out.println("Challenge received from javacard, forwarding to SP.");
			// (8).2 & (13).1 sending encryptedMsg & encryptedSymKey to SP &
			// receiving responce
			byte[] challengeResponce = service.sendChallenge(encryptedSymKey, encryptedMsg);
			System.out.println("Challenge responce receive, forwarding to javacard.");
			// TODO (13).2 send challengeResponce to javacard

			/**
			 * TODO (14)-(16) needs to be done on the javacard
			 * -------------------------
			 */

			// (14) get challenge nr & certificate name
			cph = Cipher.getInstance(algSym);
			cph.init(Cipher.DECRYPT_MODE, symKey);
			byte[] decryptedMsg = cph.doFinal(challengeResponce);
			Integer responce = (Integer) SPtools.convertToObject(decryptedMsg);

			// (15) verify responce
			if (responce != n + 1)
				throw new Exception("Incorrect challenge responce received");

			// (16) flag authenticate
			boolean auth = true;

			/**
			 * -----------------------------
			 */

			/**
			 * STEP 3: authenticate card
			 */
			// (3).1 received from SP
			byte[] encryptedChallenge = service.receiveChallenge();
			System.out.println("Challenge received from SP, forwarding to javacard");

			// TODO (3).2 send challenge to javacard
			/**
			 * TODO, (4)-(7) needs to be done on javacard
			 * ----------------------------------
			 */
			// (4) check authentication
			if (!auth)
				throw new Exception("SP is not authenticated yet!");

			// (5) decrypt the challenge
			Cipher cphr = Cipher.getInstance(algSym);
			cphr.init(Cipher.DECRYPT_MODE, symKey);
			byte[] decryptedChallenge = cph.doFinal(encryptedChallenge);
			Integer challengeNr = (Integer) SPtools.convertToObject(decryptedChallenge);

			// get common PR, dees is enkel voor in de client.java, normaal
			// heeft de javacard de private key al opgeslagen
			String keyStorePath = Paths.get(System.getProperty("user.dir")).getParent().toString() + File.separator
					+ "Certificates" + File.separator;
			String CommonKeyStore = keyStorePath + "common.jks";
			String CommonKeyPassword = "password";
			String CertificateName = "Common";
			KeyStore keyStore = KeyStore.getInstance("JKS");
			FileInputStream fis = new FileInputStream(CommonKeyStore);
			keyStore.load(fis, CommonKeyPassword.toCharArray());
			fis.close();
			PrivateKey pr = (PrivateKey) keyStore.getKey(CertificateName, CommonKeyPassword.toCharArray());
			X509Certificate cert_javaCard = (X509Certificate) keyStore.getCertificate(CertificateName);

			// (6) put signature on the challenge
			byte[] data = (challengeNr + "Auth").getBytes();
			Signature sig = Signature.getInstance("SHA1WithRSA");
			sig.initSign(pr);
			sig.update(data);
			byte[] signatureBytes = sig.sign();

			// (7) encypt certificate & signature
			Pair<X509Certificate, byte[]> msg2 = new Pair<X509Certificate, byte[]>(cert_javaCard, signatureBytes);
			cph = Cipher.getInstance(algSym);
			cph.init(Cipher.ENCRYPT_MODE, symKey);
			byte[] Emsg2 = cph.doFinal(SPtools.convertToBytes(msg2));

			/**
			 * ----------------
			 */
			// TODO (8).1 send 'Emsg2' to middelware

			// (8).2 forwarding Emsg2 to SP
			System.out.println("Challenge received from javacard, forwarding to SP.");
			service.sendChallengeResponce(Emsg2);

			/**
			 * STEP 4, query attribute releases
			 */
			// some dummy data to sent
			String User_Pin = "1234";
			String User_Name = "Mr. Bean";
			String User_Address = "Somewhere over the rainbow";
			ImageIcon User_Signature = new ImageIcon(Client.class.getResource("/signature.png"));
			Calendar tempTime = Calendar.getInstance();
			tempTime.add(Calendar.YEAR, -43);		
			Timestamp User_BirthDate = new Timestamp(tempTime.getTimeInMillis());
			String User_Gender = "M";
			ImageIcon User_Picture = new ImageIcon(Client.class.getResource("/passport_picture.jpg"));
			String User_PassportNr = "12345678";
			
			
			// TODO, (2) & (10) data query requests need to be send to the
			// javacard, the javacard needs to send the data back (if SP has the
			// rights)
			
			// (2) & (3)
			// ask for pin if no pin given yet
			int pin_attempts_left = 3;
			PinInput pinWindow = new PinInput(pin_attempts_left);
			while (true) {
				// check if attempts
				if(pin_attempts_left <= 0){
					pinWindow.close();
					System.out.println("All pincode attempts used, access denied.");
					throw new Exception("All pin attempts used.");
				}
				
				// set attempts
				pinWindow.setAttempts(pin_attempts_left);
				pin_attempts_left--;
				
				while (pinWindow.getPin() == null) {
					// wait until pin is entered by user
				}
				
				// validate pin
				if (pinWindow.getPin().equals(User_Pin)) {
					// pin OK
					System.out.println("pin OK");
					pinWindow.close();
					break;
				}
			}
			
			// (4) check SP authenticated
			if(!auth)
				throw new Exception("SP is not authenticated yet!");

			// keep accepting queries until connection closes
			SPmessage currMessage = null;
			while (currMessage == null || currMessage.getMessageType() != SPmessageType.CLOSE) {
				// await a query
				currMessage = service.awaitQuery();
				
				// check validity
				if (currMessage.getMessageType() != SPmessageType.CLOSE && !SPtools.checkRights(SPtools.getCertificateDomain(cert_SP), currMessage.getMessageType())) {
					throw new Exception("Service " + SPtools.getCertificateServiceName(cert_SP) +
							" (" + SPtools.getCertificateDomain(cert_SP) + 
							") does not have rights for " + currMessage.getMessageType());
				}
				
				switch (currMessage.getMessageType()) {
				case CLOSE:
					// close connection
					service.close();
					break;

				// request data
				case DATA_NYM:
		            MessageDigest digest = MessageDigest.getInstance("SHA-256");
		            String UniqueSynonym = User_Name + User_Address + User_BirthDate + SPtools.getCertificateServiceName(cert_SP);
		            byte[] User_nym = digest.digest(UniqueSynonym.getBytes());
		            
		            byte[] encrypted = symEncrypt(User_nym);
					cph = Cipher.getInstance(algSym);
					cph.init(Cipher.DECRYPT_MODE, symKey);
					byte[] decrypted = cph.doFinal(encrypted);
					System.out.println("orig: " + new String(User_nym));
					System.out.println("crypted: " + new String(decrypted));
		            
					service.sendData(currMessage.getMessageType(), symEncrypt(User_nym));
					break;
				case DATA_NAME:
					service.sendData(currMessage.getMessageType(), symEncrypt(User_Name));
					break;
				case DATA_ADDRESS:
					service.sendData(currMessage.getMessageType(), symEncrypt(User_Address));
					break;
				case DATA_SIGNATURE:
					service.sendData(currMessage.getMessageType(), symEncrypt(User_Signature));
					break;
				case DATA_BIRTHDATE:
					service.sendData(currMessage.getMessageType(), symEncrypt(User_BirthDate));
					break;
				case DATA_AGE:
					// calculate age
					Calendar now = Calendar.getInstance();
					now.setTimeInMillis(timestamp.getTime());
					
					Calendar birth = Calendar.getInstance();
					birth.setTimeInMillis(User_BirthDate.getTime());
					
					Integer Age = now.get(Calendar.YEAR) - birth.get(Calendar.YEAR);
					
					if (now.get(Calendar.DAY_OF_YEAR) < birth.get(Calendar.DAY_OF_YEAR))
						Age--;						
					
					service.sendData(currMessage.getMessageType(), symEncrypt(Age));
					break;
				case DATA_GENDER:
					service.sendData(currMessage.getMessageType(), symEncrypt(User_Gender));
					break;
				case DATA_PICTURE:
					service.sendData(currMessage.getMessageType(), symEncrypt(User_Picture));
					break;
				case DATA_PASSPORT:
					service.sendData(currMessage.getMessageType(), symEncrypt(User_PassportNr));
					break;

				default:
					System.out.println("Unexpected message received: " + currMessage.getMessageType());
					break;
				}
			}

			System.out.println("Everything worked!");
			// just to keep client running
			while (true) {
			}

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			c.close(); // close the connection with the card
		}
	}
	
	private static byte[] symEncrypt(Object data){
		byte[] encryptedData = null;
		
		try {
			Cipher cph;
			cph = Cipher.getInstance(algSym);
			cph.init(Cipher.ENCRYPT_MODE, symKey);
			
			try {
				encryptedData = cph.doFinal((byte[]) data);
			} catch (Exception e) {
				encryptedData = cph.doFinal(SPtools.convertToBytes(data));	
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return encryptedData;
	}
}
