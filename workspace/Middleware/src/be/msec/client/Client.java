package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;
import be.msec.government.client.GVMTimestampClient;
import be.msec.serviceProvider.client.SPClient;

import java.io.File;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;

import javax.smartcardio.*;

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

			X509Certificate cert = service.getServiceCertificate();
			// TODO send this certificate to the javacard

			/**
			 * TODO stuff to do on javacard
			 * 
			 * // verify certificate
			 * cert.verify(*CA pk*); // (2)
			 * cert.checkValidity(*lastValidationTime*); // (3)
			 */

			// just to keep client running
			while (true) {

			}

		} catch (Exception e) {
			throw e;
		} finally {
			c.close(); // close the connection with the card
		}
	}
}
