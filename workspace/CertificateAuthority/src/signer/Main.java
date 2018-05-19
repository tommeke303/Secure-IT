package signer;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

/**
 * Attempt for making a CA, but doesn't work
 * @author Pedro
 *
 */

public class Main {
	static String keyStorePath = Paths.get(System.getProperty("user.dir")).getParent().toString() + File.separator
			+ "Certificates" + File.separator;

	public static void main(String[] args) throws Exception {
		String fileName = "req";
		// sign(keyStorePath + fileName);
	}
/*
	private static void sign(String fileURL) throws Exception {
		// read the file
		byte[] encoded = Files.readAllBytes(Paths.get(fileURL));
		
		InputStream csrStream = new ByteArrayInputStream(encoded);
		

		
	    PKCS10CertificationRequest csr = convertPemToPKCS10CertificationRequest(csrStream);
	    String compname = null;

	    if (csr == null) {
	        LOG.warn("FAIL! conversion of Pem To PKCS10 Certification Request");
	    } else {
	       X500Name x500Name = csr.getSubject();

	       System.out.println("x500Name is: " + x500Name + "\n");

	       RDN cn = x500Name.getRDNs(BCStyle.EmailAddress)[0];
	       System.out.println(cn.getFirst().getValue().toString());
	       System.out.println(x500Name.getRDNs(BCStyle.EmailAddress)[0]);
	       System.out.println("COUNTRY: " + getX500Field(COUNTRY, x500Name));
	       System.out.println("STATE: " + getX500Field(STATE, x500Name));
	       System.out.println("LOCALE: " + getX500Field(LOCALE, x500Name));
	       System.out.println("ORGANIZATION: " + getX500Field(ORGANIZATION, x500Name));
	       System.out.println("ORGANIZATION_UNIT: " + getX500Field(ORGANIZATION_UNIT, x500Name));
	       System.out.println("COMMON_NAME: " + getX500Field(COMMON_NAME, x500Name));
	       System.out.println("EMAIL: " + getX500Field(EMAIL, x500Name));
	    }
		
	}
	
	private PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(InputStream pem) {
	    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	    PKCS10CertificationRequest csr = null;
	    ByteArrayInputStream pemStream = null;

	    pemStream = (ByteArrayInputStream) pem;

	    Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
	    PEMParser pemParser = null;
	    try {
	        pemParser = new PEMParser(pemReader);
	        Object parsedObj = pemParser.readObject();
	        System.out.println("PemParser returned: " + parsedObj);
	        if (parsedObj instanceof PKCS10CertificationRequest) {
	            csr = (PKCS10CertificationRequest) parsedObj;
	        }
	    } catch (IOException ex) {
	        LOG.error("IOException, convertPemToPublicKey", ex);
	    } finally {
	        if (pemParser != null) {
	            IOUtils.closeQuietly(pemParser);
	        }
	    }
	    return csr;
	}
	
	public static X509Certificate sign(PKCS10CertificationRequest inputCSR, PrivateKey caPrivate, KeyPair pair)
	        throws InvalidKeyException, NoSuchAlgorithmException,
	        NoSuchProviderException, SignatureException, IOException,
	        OperatorCreationException, CertificateException {   

	    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
	            .find("SHA1withRSA");
	    AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
	            .find(sigAlgId);

	    AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(caPrivate
	            .getEncoded());
	    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair
	            .getPublic().getEncoded());

	    PKCS10CertificationRequestHolder pk10Holder = new PKCS10CertificationRequestHolder(inputCSR);
	    //in newer version of BC such as 1.51, this is 
	    //PKCS10CertificationRequest pk10Holder = new PKCS10CertificationRequest(inputCSR);

	    X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
	            new X500Name("CN=issuer"), new BigInteger("1"), new Date(
	                    System.currentTimeMillis()), new Date(
	                    System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60
	                            * 1000), pk10Holder.getSubject(), keyInfo);

	    ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
	            .build(foo);        

	    X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
	    X509CertificateStructure eeX509CertificateStructure = holder.toASN1Structure(); 
	    //in newer version of BC such as 1.51, this is 
	    //org.spongycastle.asn1.x509.Certificate eeX509CertificateStructure = holder.toASN1Structure(); 

	    CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

	    // Read Certificate
	    InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
	    X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
	    is1.close();
	    return theCert;
	    //return null;
	}
	*/
}
