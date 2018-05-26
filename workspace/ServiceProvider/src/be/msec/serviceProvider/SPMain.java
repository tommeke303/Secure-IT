package be.msec.serviceProvider;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JLabel;
import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.JTabbedPane;
import javax.swing.JPanel;
import javax.swing.BoxLayout;
import javax.swing.GroupLayout.Alignment;

import java.awt.FlowLayout;
import java.awt.TrayIcon.MessageType;

import javax.swing.SwingConstants;
import javax.swing.JDesktopPane;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.swing.AbstractAction;
import java.awt.event.ActionEvent;
import javax.swing.Action;
import java.awt.event.ActionListener;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.awt.Window.Type;
import javax.swing.JList;
import javax.swing.AbstractListModel;
import javax.swing.border.BevelBorder;

import com.sun.net.ssl.internal.ssl.Provider;

import javafx.util.Pair;

import javax.swing.JSpinner;
import javax.swing.ListSelectionModel;
import javax.swing.JScrollPane;
import java.awt.Component;
import java.awt.Cursor;
import javax.swing.JTextArea;
import javax.swing.JRadioButton;

@SuppressWarnings("rawtypes")
public class SPMain {
	// server info
	private int ssPort = 1251;
	private ObjectOutputStream out;
	private ObjectInputStream in;

	// find keystore
	private String keyStorePath = Paths.get(System.getProperty("user.dir")).getParent().toString() + File.separator
			+ "Certificates" + File.separator;
	private String serviceProviderKeyStore = keyStorePath + "ServiceProvider.jks";
	private String serviceProviderKeyPassword = "password";
	
	// encryption variables
	private String algAsym = "RSA/ECB/PKCS1Padding";
	private String algSym = "AES";
	private PrivateKey pr;
	private SecretKeySpec symKey;
	private X509Certificate chosenCert;

	// window info
	private JFrame frmFrame;
	private JPanel tabWaiting;
	private JPanel tabDefault;
	private JPanel tabEGov;
	private JPanel tabBank;
	private JPanel tabExtra;
	private JTabbedPane tabbedPane;

	private String[] valuesEGov = new String[] { "MyPension", "Tax-On-Web",  };
	private String[] valuesBank = new String[] { "ING", "KBC" };
	private String[] valuesExtra = new String[] { "Eye-Institute-Aalst", "Wellness-Kliniek-Genk" };
	private String[] valuesDefault = new String[] { "GameCenter", "VendingMachine" };

	private JList lstEGov;
	private JList lstDefault;
	private JList lstExtra;
	private JList lstBank;
	private boolean isWaitingForNewConnection = true;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					SPMain window = new SPMain();
					window.frmFrame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 * 
	 * @throws Exception
	 */
	public SPMain() throws Exception {
		// make window
		initialize();

		new Thread(new Runnable() {

			@Override
			public void run() {
				try {
					// set security properties
					Security.addProvider(new Provider());
					System.setProperty("javax.net.ssl.keyStore", serviceProviderKeyStore);
					System.setProperty("javax.net.ssl.keyStorePassword", serviceProviderKeyPassword);

					// make ssl server socket
					SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
					SSLServerSocket ssocket = (SSLServerSocket) factory.createServerSocket(ssPort);

					// feedback
					System.out.println("Service provider started and ready for accepting connections");
					while (true) {
						// wait until previous is done
						while (!isWaitingForNewConnection) {
						}
						
						// accept new connection
						Socket socket = ssocket.accept();
						out = new ObjectOutputStream(socket.getOutputStream());
						in = new ObjectInputStream(socket.getInputStream());
						System.out.println("\nNew connection accepted.");

						SPmessage currMessage = new SPmessage(SPmessageType.SP_CERTIFICATE);

						// TODO process messages
						// show service selection
						getTabbedPane();
						while (currMessage.getMessageType() != SPmessageType.CLOSE) {
							currMessage = (SPmessage) in.readObject();
							
							// check message type
							switch (currMessage.getMessageType()) {
							// close connection
							case CLOSE:
								in.close();
								out.close();

								isWaitingForNewConnection = true;
								break;

							// receive a challenge
							case AUTH_SP:
								System.out.println("Challenge received from middelware.");
								
								// generate responce							
								byte[] responce = generateChallengeResponce(currMessage);
								
								// sent back the responce
								out.writeObject(new SPmessage(SPmessageType.AUTH_SP, responce));
								System.out.println("Challenge responce sent.");
								
								
							break;
								
							default:
								System.out.println("Message type not implemented: " + currMessage.getMessageType());
								break;
							}
						}
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}).start();
	}

	/**
	 * Initialize the contents of the frame.
	 */

	private void initialize() {
		frmFrame = new JFrame();
		frmFrame.setBounds(100, 100, 311, 185);
		frmFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmFrame.setMinimumSize(new Dimension(300, 250));
		frmFrame.getContentPane().setLayout(new BorderLayout(0, 0));

		tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		tabbedPane.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
		frmFrame.getContentPane().add(tabbedPane);

		// show waiting
		getWaitingPanel();
		//getTabbedPane();
	}

	@SuppressWarnings({ "unchecked", "serial" })
	private void getTabbedPane() {
		isWaitingForNewConnection = false;

		frmFrame.setTitle("Select a service");

		if (tabWaiting != null)
			tabbedPane.removeTabAt(tabbedPane.indexOfComponent(tabWaiting));

		tabEGov = new JPanel();
		tabbedPane.addTab("eGov", null, tabEGov, null);
		tabEGov.setLayout(new BorderLayout(0, 0));

		JScrollPane spEGov = new JScrollPane();
		spEGov.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
		tabEGov.add(spEGov, BorderLayout.CENTER);

		lstEGov = new JList();
		lstEGov.setModel(new AbstractListModel() {
			public int getSize() {
				return valuesEGov.length;
			}

			public Object getElementAt(int index) {
				return valuesEGov[index];
			}
		});

		lstEGov.setSelectedIndex(0);
		spEGov.setViewportView(lstEGov);

		JButton btnEGov = new JButton("Select");
		btnEGov.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				selectService(lstEGov.getSelectedValue().toString());
			}
		});
		btnEGov.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		btnEGov.setAlignmentY(Component.BOTTOM_ALIGNMENT);
		btnEGov.setAlignmentX(Component.CENTER_ALIGNMENT);
		tabEGov.add(btnEGov, BorderLayout.SOUTH);

		tabBank = new JPanel();
		tabbedPane.addTab("Bank", null, tabBank, null);
		tabBank.setLayout(new BorderLayout(0, 0));

		JScrollPane spBank = new JScrollPane();
		tabBank.add(spBank);

		lstBank = new JList();
		lstBank.setModel(new AbstractListModel() {
			public int getSize() {
				return valuesBank.length;
			}

			public Object getElementAt(int index) {
				return valuesBank[index];
			}
		});
		lstBank.setSelectedIndex(0);
		spBank.setViewportView(lstBank);

		JButton btnBank = new JButton("Select");
		btnBank.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				selectService(lstBank.getSelectedValue().toString());
			}
		});
		btnBank.setAlignmentY(1.0f);
		btnBank.setAlignmentX(0.5f);
		tabBank.add(btnBank, BorderLayout.SOUTH);

		tabExtra = new JPanel();
		tabbedPane.addTab("Clinic", null, tabExtra, null);
		tabExtra.setLayout(new BorderLayout(0, 0));

		JScrollPane spExtra = new JScrollPane();
		tabExtra.add(spExtra);

		lstExtra = new JList();
		lstExtra.setModel(new AbstractListModel() {
			public int getSize() {
				return valuesExtra.length;
			}

			public Object getElementAt(int index) {
				return valuesExtra[index];
			}
		});
		lstExtra.setSelectedIndex(0);
		spExtra.setViewportView(lstExtra);

		JButton btnExtra = new JButton("Select");
		btnExtra.setAlignmentY(1.0f);
		btnExtra.setAlignmentX(0.5f);
		btnExtra.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				selectService(lstExtra.getSelectedValue().toString());
			}
		});
		tabExtra.add(btnExtra, BorderLayout.SOUTH);

		tabDefault = new JPanel();
		tabDefault.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
		tabbedPane.addTab("Default", null, tabDefault, null);
		tabDefault.setLayout(new BorderLayout(0, 0));

		JScrollPane spDefault = new JScrollPane();
		tabDefault.add(spDefault, BorderLayout.CENTER);

		lstDefault = new JList();
		lstDefault.setModel(new AbstractListModel() {
			public int getSize() {
				return valuesDefault.length;
			}

			public Object getElementAt(int index) {
				return valuesDefault[index];
			}
		});
		lstDefault.setSelectedIndex(0);
		spDefault.setViewportView(lstDefault);

		JButton btnDefault = new JButton("Select");
		btnDefault.setAlignmentY(1.0f);
		btnDefault.setAlignmentX(0.5f);
		btnDefault.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				selectService(lstDefault.getSelectedValue().toString());
			}
		});
		tabDefault.add(btnDefault, BorderLayout.SOUTH);
	}

	private void getWaitingPanel() {
		frmFrame.setTitle("Waiting");
		if (tabEGov != null) {
			tabbedPane.removeTabAt(tabbedPane.indexOfComponent(tabBank));
			tabbedPane.removeTabAt(tabbedPane.indexOfComponent(tabDefault));
			tabbedPane.removeTabAt(tabbedPane.indexOfComponent(tabEGov));
			tabbedPane.removeTabAt(tabbedPane.indexOfComponent(tabExtra));
		}

		tabWaiting = new JPanel();
		tabbedPane.addTab("Waiting", null, tabWaiting, null);

		JLabel lblWaiting = new JLabel("Please insert card...");
		tabWaiting.add(lblWaiting);
		lblWaiting.setVerticalAlignment(SwingConstants.TOP);
		lblWaiting.setHorizontalTextPosition(SwingConstants.CENTER);
		lblWaiting.setHorizontalAlignment(SwingConstants.CENTER);
	}

	private void selectService(String serviceName) {
		System.out.println("Chosen service: " + serviceName);
		
		// find keystore
		String keyStorePath = Paths.get(System.getProperty("user.dir")).getParent().toString() + File.separator
				+ "Certificates" + File.separator + "Services" + File.separator;
		String ServiceKeyStore = keyStorePath + serviceName + ".jks";
		String ServicePassword = "password";
		String CertificateName = serviceName;

		// get certificate
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			FileInputStream fis = new FileInputStream(ServiceKeyStore);
			ks.load(fis, ServicePassword.toCharArray());
			fis.close();

			// remember private key during session
			pr = (PrivateKey) ks.getKey(CertificateName, ServicePassword.toCharArray());
			
			// get certificate
			chosenCert = (X509Certificate) ks.getCertificate(CertificateName);
			
			// send certificate
			out.writeObject(new SPmessage(SPmessageType.SP_CERTIFICATE, chosenCert));
			System.out.println("Certificate sent");

			// show waiting again
			getWaitingPanel();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// part of STEP 2, generating a responce for the challenge
	@SuppressWarnings("unchecked")
	private byte[] generateChallengeResponce(SPmessage challengeMessage){
		// get the Ekey & Emsg from the SPmessage
		Pair<byte[], byte[]> data = (Pair<byte[], byte[]>) challengeMessage.getData();
		byte[] Ekey = data.getKey();
		byte[] Emsg = data.getValue();
		
		byte[] responce = null;
		try {
			// (9) get symmetric key
			Cipher cph;
			cph = Cipher.getInstance(algAsym);
			cph.init(Cipher.DECRYPT_MODE, pr);
			byte[] decryptedSymKey = cph.doFinal(Ekey);
			symKey = new SecretKeySpec(decryptedSymKey, 0, decryptedSymKey.length, "AES");

			// (10) get challenge nr & certificate name
			cph = Cipher.getInstance(algSym);
			cph.init(Cipher.DECRYPT_MODE, symKey);
			byte[] decryptedMsg = cph.doFinal(Emsg);
			Pair<Integer, String> msg = (Pair<Integer, String>) SPtools.convertToObject(decryptedMsg);

			// (11) check name, abort if incorrect
			String msgName = msg.getValue();
			String expectedName = chosenCert.getSubjectDN().getName();
			if (!msgName.equals(expectedName))
		        throw new Exception("Received '" + msgName + "', expected '" + expectedName + "'");
			
			// (12) incr challenge & encrypt with symmetric key
			cph = Cipher.getInstance(algSym);
			cph.init(Cipher.ENCRYPT_MODE, symKey);
			responce = cph.doFinal(SPtools.convertToBytes(msg.getKey() + 1));
		} catch (Exception e) {
			e.printStackTrace();
		} 
		
		return responce;		
	}
}
