package be.msec.smartcard;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.nio.file.Paths;


import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

import javafx.util.Pair;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.PublicKey;

public class IdentityCard extends Applet {
	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;

	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte HELLO = 0x24;
	private static final byte SIG_TIME = 0x26;
	private static final byte SEND_BIG_DATA = 0x30;
	private static final byte AUTHENTICATESP = 0x34;
	private static final byte RETRIEVE_KEY = 0x32;
	private static final byte RETRIEVE_MSG = 0x36;
	
	private final static byte PIN_TRY_LIMIT = (byte) 0x03;
	private final static byte PIN_SIZE = (byte) 0x04;

	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	private byte[] privModulus = new byte[] { (byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 82, (byte) 25,
			(byte) -66, (byte) 34, (byte) 5, (byte) -58, (byte) 75, (byte) -39, (byte) -54, (byte) 43, (byte) 25,
			(byte) -117, (byte) 80, (byte) -62, (byte) 51, (byte) 19, (byte) 59, (byte) -70, (byte) -100, (byte) 85,
			(byte) 24, (byte) -57, (byte) 108, (byte) -98, (byte) -2, (byte) 1, (byte) -80, (byte) -39, (byte) 63,
			(byte) 93, (byte) 112, (byte) 7, (byte) 4, (byte) 18, (byte) -11, (byte) -98, (byte) 17, (byte) 126,
			(byte) -54, (byte) 27, (byte) -56, (byte) 33, (byte) 77, (byte) -111, (byte) -74, (byte) -78, (byte) 88,
			(byte) 70, (byte) -22, (byte) -3, (byte) 15, (byte) 16, (byte) 37, (byte) -18, (byte) 92, (byte) 74,
			(byte) 124, (byte) -107, (byte) -116, (byte) -125 };
	private byte[] privExponent = new byte[] { (byte) 24, (byte) 75, (byte) 93, (byte) -79, (byte) 62, (byte) 33,
			(byte) 98, (byte) -52, (byte) 50, (byte) 65, (byte) 43, (byte) -125, (byte) 3, (byte) -63, (byte) -64,
			(byte) 101, (byte) 117, (byte) -19, (byte) -60, (byte) 60, (byte) 53, (byte) 119, (byte) -118, (byte) -13,
			(byte) -128, (byte) 11, (byte) -46, (byte) -30, (byte) 12, (byte) 37, (byte) -125, (byte) 14, (byte) 104,
			(byte) -5, (byte) -15, (byte) -120, (byte) -113, (byte) -49, (byte) -70, (byte) -78, (byte) 114, (byte) 122,
			(byte) 34, (byte) 114, (byte) -99, (byte) -102, (byte) 43, (byte) -43, (byte) -102, (byte) 71, (byte) 115,
			(byte) 116, (byte) -105, (byte) -48, (byte) -80, (byte) 109, (byte) 117, (byte) 106, (byte) 88, (byte) 6,
			(byte) -69, (byte) -42, (byte) -83, (byte) 25 };

	private byte[] certificate = new byte[] { (byte) 48, (byte) -126, (byte) 1, (byte) -67, (byte) 48, (byte) -126,
			(byte) 1, (byte) 103, (byte) -96, (byte) 3, (byte) 2, (byte) 1, (byte) 2, (byte) 2, (byte) 5, (byte) 0,
			(byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42,
			(byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 5, (byte) 5, (byte) 0,
			(byte) 48, (byte) 100, (byte) 49, (byte) 11, (byte) 48, (byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4,
			(byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69, (byte) 49, (byte) 13, (byte) 48, (byte) 11, (byte) 6,
			(byte) 3, (byte) 85, (byte) 4, (byte) 7, (byte) 12, (byte) 4, (byte) 71, (byte) 101, (byte) 110, (byte) 116,
			(byte) 49, (byte) 25, (byte) 48, (byte) 23, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12,
			(byte) 16, (byte) 75, (byte) 97, (byte) 72, (byte) 111, (byte) 32, (byte) 83, (byte) 105, (byte) 110,
			(byte) 116, (byte) 45, (byte) 76, (byte) 105, (byte) 101, (byte) 118, (byte) 101, (byte) 110, (byte) 49,
			(byte) 20, (byte) 48, (byte) 18, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 11, (byte) 12, (byte) 11,
			(byte) 86, (byte) 97, (byte) 107, (byte) 103, (byte) 114, (byte) 111, (byte) 101, (byte) 112, (byte) 32,
			(byte) 73, (byte) 84, (byte) 49, (byte) 21, (byte) 48, (byte) 19, (byte) 6, (byte) 3, (byte) 85, (byte) 4,
			(byte) 3, (byte) 12, (byte) 12, (byte) 74, (byte) 97, (byte) 110, (byte) 32, (byte) 86, (byte) 111,
			(byte) 115, (byte) 115, (byte) 97, (byte) 101, (byte) 114, (byte) 116, (byte) 48, (byte) 32, (byte) 23,
			(byte) 13, (byte) 49, (byte) 48, (byte) 48, (byte) 50, (byte) 50, (byte) 52, (byte) 48, (byte) 57,
			(byte) 52, (byte) 51, (byte) 48, (byte) 50, (byte) 90, (byte) 24, (byte) 15, (byte) 53, (byte) 49,
			(byte) 55, (byte) 57, (byte) 48, (byte) 49, (byte) 48, (byte) 57, (byte) 49, (byte) 57, (byte) 50,
			(byte) 57, (byte) 52, (byte) 50, (byte) 90, (byte) 48, (byte) 100, (byte) 49, (byte) 11, (byte) 48,
			(byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69,
			(byte) 49, (byte) 13, (byte) 48, (byte) 11, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 7, (byte) 12,
			(byte) 4, (byte) 71, (byte) 101, (byte) 110, (byte) 116, (byte) 49, (byte) 25, (byte) 48, (byte) 23,
			(byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12, (byte) 16, (byte) 75, (byte) 97, (byte) 72,
			(byte) 111, (byte) 32, (byte) 83, (byte) 105, (byte) 110, (byte) 116, (byte) 45, (byte) 76, (byte) 105,
			(byte) 101, (byte) 118, (byte) 101, (byte) 110, (byte) 49, (byte) 20, (byte) 48, (byte) 18, (byte) 6,
			(byte) 3, (byte) 85, (byte) 4, (byte) 11, (byte) 12, (byte) 11, (byte) 86, (byte) 97, (byte) 107,
			(byte) 103, (byte) 114, (byte) 111, (byte) 101, (byte) 112, (byte) 32, (byte) 73, (byte) 84, (byte) 49,
			(byte) 21, (byte) 48, (byte) 19, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 3, (byte) 12, (byte) 12,
			(byte) 74, (byte) 97, (byte) 110, (byte) 32, (byte) 86, (byte) 111, (byte) 115, (byte) 115, (byte) 97,
			(byte) 101, (byte) 114, (byte) 116, (byte) 48, (byte) 92, (byte) 48, (byte) 13, (byte) 6, (byte) 9,
			(byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 1,
			(byte) 5, (byte) 0, (byte) 3, (byte) 75, (byte) 0, (byte) 48, (byte) 72, (byte) 2, (byte) 65, (byte) 0,
			(byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 82, (byte) 25, (byte) -66, (byte) 34, (byte) 5,
			(byte) -58, (byte) 75, (byte) -39, (byte) -54, (byte) 43, (byte) 25, (byte) -117, (byte) 80, (byte) -62,
			(byte) 51, (byte) 19, (byte) 59, (byte) -70, (byte) -100, (byte) 85, (byte) 24, (byte) -57, (byte) 108,
			(byte) -98, (byte) -2, (byte) 1, (byte) -80, (byte) -39, (byte) 63, (byte) 93, (byte) 112, (byte) 7,
			(byte) 4, (byte) 18, (byte) -11, (byte) -98, (byte) 17, (byte) 126, (byte) -54, (byte) 27, (byte) -56,
			(byte) 33, (byte) 77, (byte) -111, (byte) -74, (byte) -78, (byte) 88, (byte) 70, (byte) -22, (byte) -3,
			(byte) 15, (byte) 16, (byte) 37, (byte) -18, (byte) 92, (byte) 74, (byte) 124, (byte) -107, (byte) -116,
			(byte) -125, (byte) 2, (byte) 3, (byte) 1, (byte) 0, (byte) 1, (byte) 48, (byte) 13, (byte) 6, (byte) 9,
			(byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 5,
			(byte) 5, (byte) 0, (byte) 3, (byte) 65, (byte) 0, (byte) 33, (byte) 97, (byte) 121, (byte) -25, (byte) 43,
			(byte) -47, (byte) 113, (byte) -104, (byte) -11, (byte) -42, (byte) -46, (byte) -17, (byte) 1, (byte) -38,
			(byte) 50, (byte) 59, (byte) -63, (byte) -74, (byte) -33, (byte) 90, (byte) 92, (byte) -59, (byte) 99,
			(byte) -17, (byte) -60, (byte) 17, (byte) 25, (byte) 79, (byte) 68, (byte) 68, (byte) -57, (byte) -8,
			(byte) -64, (byte) 35, (byte) -19, (byte) -114, (byte) 110, (byte) -116, (byte) 31, (byte) -126, (byte) -24,
			(byte) 54, (byte) 71, (byte) 82, (byte) -53, (byte) -78, (byte) -84, (byte) -45, (byte) -83, (byte) 87,
			(byte) 68, (byte) 124, (byte) -1, (byte) -128, (byte) -49, (byte) 124, (byte) 103, (byte) 28, (byte) 56,
			(byte) -114, (byte) -10, (byte) 97, (byte) -78, (byte) 54 };

	private OwnerPIN pin;
	private byte[] lastValidationTimeByteArray;
	private byte[] pkByteArray;
	private byte[] prByteArray;
	private byte[] bigByteArray;
	private byte[] encryptedSymKey;
	private byte[] encryptedMsg;
	
	/*
	// make private key?
	short offset = 0;
	short keySizeInBytes=64;
	short keySizeInBits = 512;
	RSAPrivateKey privkey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keySizeInBits, false);
	privKey.setExponent(privExponent, offset, keySizeInBytes);
	privKey.setModulus(privModulus, offset, keySizeInBytes);

	// digital signature?
	Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
	signature.init(privKey, Signature.MODE_SIGN) ;
	short sigLength = signature.sign(input, offset, length, output, 0) ;
	 */
	 
	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created.
		 * In this example, this is the 'pin' object.
		 */
		pin = new OwnerPIN(PIN_TRY_LIMIT,PIN_SIZE);
		pin.update(new byte[]{0x01,0x02,0x03,0x04},(short) 0, PIN_SIZE);
		
		/*
		 * Initialising the lastValidationTime to the time of creation
		 */
		lastValidationTimeByteArray = convertToBytes(new Timestamp(System.currentTimeMillis()));
		try {
			// get public key, dees is enkel voor in de client.java, normaal
			// heeft de javacard de public key van government al opgeslagen
			/* String keyStorePath = Paths.get(System.getProperty("user.dir")).getParent().toString() + File.separator
					+ "Certificates" + File.separator; */
			
			String keyStorePath = "/Users/Thomas/eclipse-workspace/Secure-IT/workspace/Certificates/";
			// /Users/Thomas/eclipse-workspace/Secure-IT/workspace/Certificates/
			
			String ClientKeyStore = keyStorePath + "common.jks";
			String ClientKeyPassword = "password";
			String CertificateName = "government (ca)";
			KeyStore keyStore = KeyStore.getInstance("JKS");
			FileInputStream fis = new FileInputStream(ClientKeyStore);
			keyStore.load(fis, ClientKeyPassword.toCharArray());	
			fis.close();
			PublicKey pk = keyStore.getCertificate(CertificateName).getPublicKey();
			PrivateKey pr = (PrivateKey) keyStore.getKey("common", ClientKeyPassword.toCharArray());
			
			pkByteArray = convertToBytes(pk);
			prByteArray = convertToBytes(pr);
			
		}catch(Exception ex) {
			System.out.println(ex);
		}
		
		
		
		/*
		 * This method registers the applet with the JCRE on the card.
		 */
		register();
	}

	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new IdentityCard();
	}

	/*
	 * If no tries are remaining, the applet refuses selection. The card can,
	 * therefore, no longer be used for identification.
	 */
	public boolean select() {
		if (pin.getTriesRemaining() == 0)
			return false;
		return true;
	}

	/*
	 * This method is called when the applet is selected and an APDU arrives.
	 */
	public void process(APDU apdu) throws ISOException {
		
		// A reference to the buffer, where the APDU data is stored, is
		// retrieved.
		byte[] buffer = apdu.getBuffer();
		

		// If the APDU selects the applet, no further processing is required.
		if (this.selectingApplet())
			return;

		// Check whether the indicated class of instructions is compatible with
		// this applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		// A switch statement is used to select a method depending on the
		// instruction
		switch (buffer[ISO7816.OFFSET_INS]) {
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		
		case SIG_TIME:
			sign(apdu);
			break;
		case SEND_BIG_DATA:
			receive_big_data(apdu);
			break;
		case AUTHENTICATESP:
			verify_certificate(apdu);
			break;
		case RETRIEVE_KEY:
			retrieve_key(apdu);
			break;
		case RETRIEVE_MSG:
			retrieve_msg(apdu);
			break;
		case HELLO:
			reqRevalidation(apdu);
			break;
		// If no matching instructions are found it is indicated in the status
		// word of the response.
		// This can be done by using this method. As an argument a short is
		// given that indicates
		// the type of warning. There are several predefined warnings in the
		// 'ISO7816' class.
		default:
			
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	/*
	 * This method is used to authenticate the owner of the card using a PIN
	 * code.
	 */
	private void validatePIN(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		// The input data needs to be of length 'PIN_SIZE'.
		// Note that the byte values in the Lc and Le fields represent values
		// between
		// 0 and 255. Therefore, if a short representation is required, the
		// following
		// code needs to be used: short Lc = (short) (buffer[ISO7816.OFFSET_LC]
		// & 0x00FF);
		if (buffer[ISO7816.OFFSET_LC] == PIN_SIZE) {
			// This method is used to copy the incoming data in the APDU buffer.
			apdu.setIncomingAndReceive();
			// Note that the incoming APDU data size may be bigger than the APDU
			// buffer
			// size and may, therefore, need to be read in portions by the
			// applet.
			// Most recent smart cards, however, have buffers that can contain
			// the maximum
			// data size. This can be found in the smart card specifications.
			// If the buffer is not large enough, the following method can be
			// used:
			//
			// byte[] buffer = apdu.getBuffer();
			// short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
			// Util.arrayCopy(buffer, START, storage, START, (short)5);
			// short readCount = apdu.setIncomingAndReceive();
			// short i = ISO7816.OFFSET_CDATA;
			// while ( bytesLeft > 0){
			// Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i,
			// readCount);
			// bytesLeft -= readCount;
			// i+=readCount;
			// readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
			// }
			if (pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_SIZE) == false)
				ISOException.throwIt(SW_VERIFICATION_FAILED);
		} else
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}

	private byte[] read_Data(APDU apdu) {
		
		byte buffer[] = apdu.getBuffer();
		short length = (short) buffer[ISO7816.OFFSET_LC];
		byte[] temp = new byte[length];
		
		short offset = 0;
		short readCount = apdu.setIncomingAndReceive();
		
		while(length >0) {
			for (short i = 0; i<readCount; i++) {
				temp[offset + i] = buffer[ISO7816.OFFSET_CDATA + offset + i];
			}
			length -= readCount;
			offset += readCount;
			readCount = apdu.receiveBytes (ISO7816.OFFSET_CDATA);
		}
		
		return temp;
	}
	
	private void retrieve_key(APDU apdu) {
		// If the pin is not validated, a response APDU with the
		// 'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if (!pin.isValidated()) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
		else {
			encryptedSymKey = (byte[])read_byte_array_from_data(apdu) ;
		}
	}
	
	private void retrieve_msg(APDU apdu) {
		// If the pin is not validated, a response APDU with the
		// 'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if (!pin.isValidated()) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
		else {
			encryptedMsg = (byte[])read_byte_array_from_data(apdu) ;
		}
	}
	
	private void receive_big_data(APDU apdu) {
		
		byte incomingByteArray[] = read_Data(apdu);
		byte[] newBigByteArray;
		if (bigByteArray != null) {
			newBigByteArray = new byte[bigByteArray.length + incomingByteArray.length];
			System.arraycopy(bigByteArray, 0, newBigByteArray, 0, bigByteArray.length);
			System.arraycopy(incomingByteArray, 0, newBigByteArray, bigByteArray.length, incomingByteArray.length);
		}
		else {
			newBigByteArray = new byte[incomingByteArray.length];
			System.arraycopy(incomingByteArray, 0, newBigByteArray, 0, incomingByteArray.length);
		}
		bigByteArray = newBigByteArray;
		
	}
	
	private Object read_byte_array_from_data(APDU apdu) {
		Object o;
		if (bigByteArray != null) {
			o = convertToObject(bigByteArray);
			bigByteArray = null;
		}
		else {
			o = convertToObject(read_Data(apdu));
		}
		return o;
	}
	
	private void sign(APDU apdu) {
		// If the pin is not validated, a response APDU with the
		// 'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if (!pin.isValidated()) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
		else {
			Pair<byte[], Timestamp> encryptedTimestamp = (Pair<byte[], Timestamp>)read_byte_array_from_data(apdu) ;
			
			// (10) verify timestamp
			PublicKey pk = (PublicKey) convertToObject(pkByteArray);
			Signature sig = null;
			boolean verified = false;
			try {
				sig = Signature.getInstance("SHA1WithRSA");
				sig.initVerify(pk);
				sig.update(convertToBytes(encryptedTimestamp.getValue()));
				verified = sig.verify(encryptedTimestamp.getKey());
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				System.out.println(e1);
			}
			
			
			
			if (!verified) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}

			// (11) check if new time is actually new
			Timestamp lastValidationTime = null;
			
			try {
				lastValidationTime = convertBytesToTimestamp(lastValidationTimeByteArray);
			}
			catch(Exception e) {
				System.out.println(e);
			}
			
			if (lastValidationTime.getTime() >= encryptedTimestamp.getValue().getTime()) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
				

			// (12) set new time in memory
			lastValidationTime = encryptedTimestamp.getValue();
		}
	}
	
	private void verify_certificate(APDU apdu) {
		// If the pin is not validated, a response APDU with the
		// 'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if (!pin.isValidated()) {
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		}
		else {
			try {
				X509Certificate cert_SP = (X509Certificate)read_byte_array_from_data(apdu);
				
				// (2) check validity of certificate
				PublicKey pk = (PublicKey) convertToObject(pkByteArray);
				cert_SP.verify(pk);
				
				// (3) check time validity of the certificate
				Timestamp lastValidationTime = convertBytesToTimestamp(lastValidationTimeByteArray);
				cert_SP.checkValidity(lastValidationTime);
				
			}
			catch(Exception e) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			}
		}
			
			
	}

	private void reqRevalidation(APDU apdu) {
		
		// If the pin is not validated, a response APDU with the
		// 'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
			
			Calendar cal = Calendar.getInstance();
			short res;
			
			Timestamp validTime = null;
			Timestamp currentTime = null;
			
			try {
				validTime = convertBytesToTimestamp(lastValidationTimeByteArray);
				currentTime = convertBytesToTimestamp(read_Data(apdu));
			}
			catch(Exception e) {
				System.out.println(e);
			}
			
			cal.setTimeInMillis(validTime.getTime());
			cal.add(Calendar.HOUR, 24);
			validTime = new Timestamp(cal.getTime().getTime());
			
			if (validTime.before(currentTime)) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
		}
	}
	
	private static Timestamp convertBytesToTimestamp(byte[] timeByteArray) {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSS");
		Date parsedDate = null;
		try {
			parsedDate = dateFormat.parse(String.valueOf(convertToObject(timeByteArray)));
		}
		catch(Exception e) {
			System.out.println(e);
		}
		
		return new Timestamp(parsedDate.getTime());
	}
	
	// encode something to bytes
	private static byte[] convertToBytes(Object input) {
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
	
	// decode something to bytes
	private static Object convertToObject(byte[] yourBytes) {
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
