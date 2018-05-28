package be.msec.serviceProvider.tools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.cert.X509Certificate;

import be.msec.serviceProvider.SPdomain;
import be.msec.serviceProvider.SPmessageType;

public class SPtools {
	// search for an attribute
	public static String getCertificateServiceName(X509Certificate cert) {
		return getCertificateAttribute(cert, "CN");
	}

	public static SPdomain getCertificateDomain(X509Certificate cert) {
		String domainname = getCertificateAttribute(cert, "DC").toUpperCase();
		
		// generate the domain enum
		SPdomain result = null;
		switch (domainname) {
		case "EGOV":
			result = SPdomain.Egov;
			break;
		case "BANK":
			result = SPdomain.Bank;
			break;
		case "CLINIC":
			result = SPdomain.Clinic;
			break;
		case "DEFAULT":
			result = SPdomain.Default;
			break;

		default:
			System.out.println("Unknown domain: " + domainname);
			result = null;
			break;
		}
		
		return result;
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

	// encode something to bytes
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

	// decode something to bytes
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

	/**
	 * Check if SP has the rights to request this data query
	 * @param dm
	 * @param msgType
	 * @return true if ok, false if no right
	 */
	public static boolean checkRights(SPdomain dm, SPmessageType msgType) {
		switch (dm) {
		case Egov:
			switch (msgType) {
			case AUTH_CARD:
			case AUTH_SP:
			case CLOSE:
			case SP_CERTIFICATE:
				return false;

			default:
				// accept all
				return true;
			}

		case Bank:
			switch (msgType) {
			case DATA_NYM:
			case DATA_NAME:
			case DATA_ADDRESS:
			case DATA_SIGNATURE:
			case DATA_AGE:
				return true;

			default:
				return false;
			}

		case Clinic:
			switch (msgType) {
			case DATA_NYM:
			case DATA_NAME:
			case DATA_ADDRESS:
			case DATA_SIGNATURE:
			case DATA_AGE:
			case DATA_GENDER:
				return true;

			default:
				return false;
			}

		case Default:
			switch (msgType) {
			case DATA_NYM:
			case DATA_AGE:
				return true;

			default:
				return false;
			}

		default:
			return false;
		}
	}
}
