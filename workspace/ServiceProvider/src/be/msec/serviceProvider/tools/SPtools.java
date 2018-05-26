package be.msec.serviceProvider.tools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.cert.X509Certificate;

public class SPtools {
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
}
