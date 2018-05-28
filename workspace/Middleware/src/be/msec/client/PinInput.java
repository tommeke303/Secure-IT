package be.msec.client;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.JLabel;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.DocumentFilter;
import javax.swing.text.PlainDocument;

import java.awt.Font;
import javax.swing.JButton;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JPasswordField;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.WindowEvent;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class PinInput {
	private String pin = "";

	private JFrame frmPinCode;
	private JPasswordField txtPinCode;

	private JLabel lblAttempsleft;

	private JButton btnOk;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					new PinInput(3);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	
	public String getPin(){
		return pin;
	}

	/**
	 * Create the application.
	 */
	public PinInput(int attemptsLeft) {
		// set pin to null again
		pin = null;
		
		initialize(attemptsLeft);
		this.frmPinCode.setVisible(true);
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize(int attemptsLeft) {
		frmPinCode = new JFrame();
		frmPinCode.setBounds(100, 100, 233, 159);
		frmPinCode.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmPinCode.getContentPane().setLayout(new BorderLayout(0, 0));
		frmPinCode.setMinimumSize(new Dimension(233, 139));

		JPanel panel = new JPanel();
		frmPinCode.getContentPane().add(panel);

		btnOk = new JButton("OK");
		btnOk.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				// set pin
				pin = new String(txtPinCode.getPassword());
			}
		});
		btnOk.setEnabled(false);

		txtPinCode = new JPasswordField();
		txtPinCode.addKeyListener(new KeyListener() {
			private void updateButton(){
				if(new String(txtPinCode.getPassword()).equals(""))
					btnOk.setEnabled(false);
				else
					btnOk.setEnabled(true);
			}
			
			@Override
			public void keyTyped(KeyEvent e) {
			}
			
			@Override
			public void keyReleased(KeyEvent e) {
				updateButton();
			}
			
			@Override
			public void keyPressed(KeyEvent e) {
				updateButton();
			}
		});

		PlainDocument doc = (PlainDocument) txtPinCode.getDocument();
		doc.setDocumentFilter(new MyIntFilter());

		JLabel lblEnterPinCode = new JLabel("Enter pin code:");
		lblEnterPinCode.setFont(new Font("Tahoma", Font.BOLD, 18));
		
		JLabel lblAttempsAvailable = new JLabel("Attemps available:");
		
		lblAttempsleft = new JLabel(attemptsLeft + "");
		GroupLayout gl_panel = new GroupLayout(panel);
		gl_panel.setHorizontalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel.createSequentialGroup()
					.addGap(41)
					.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel.createSequentialGroup()
							.addComponent(lblAttempsAvailable)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(lblAttempsleft))
						.addGroup(gl_panel.createSequentialGroup()
							.addComponent(txtPinCode, GroupLayout.PREFERRED_SIZE, 74, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(btnOk))
						.addComponent(lblEnterPinCode))
					.addContainerGap(35, Short.MAX_VALUE))
		);
		gl_panel.setVerticalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel.createSequentialGroup()
					.addGap(23)
					.addComponent(lblEnterPinCode)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addGroup(gl_panel.createParallelGroup(Alignment.BASELINE)
						.addComponent(txtPinCode, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(btnOk, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(gl_panel.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblAttempsAvailable)
						.addComponent(lblAttempsleft))
					.addContainerGap(23, Short.MAX_VALUE))
		);
		panel.setLayout(gl_panel);
	}
	
	public void setAttempts(int n){
		txtPinCode.setText("");
		btnOk.setEnabled(false);
		pin = null;
		
		
		lblAttempsleft.setText(n + "");
	}
	
	public void close(){
		frmPinCode.setVisible(false);
	}

	class MyIntFilter extends DocumentFilter {
		@Override
		public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
				throws BadLocationException {

			Document doc = fb.getDocument();
			StringBuilder sb = new StringBuilder();
			sb.append(doc.getText(0, doc.getLength()));
			sb.insert(offset, string);

			if (test(sb.toString())) {
				super.insertString(fb, offset, string, attr);
			} else {
				// warn the user and don't allow the insert
			}
		}

		private boolean test(String text) {
			try {
				Integer.parseInt(text);

				return true;
			} catch (NumberFormatException e) {
				if (text.equals("")) 
					return true;
				return false;
			}
		}

		@Override
		public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs)
				throws BadLocationException {

			Document doc = fb.getDocument();
			StringBuilder sb = new StringBuilder();
			sb.append(doc.getText(0, doc.getLength()));
			sb.replace(offset, offset + length, text);

			if (test(sb.toString())) {
				super.replace(fb, offset, length, text, attrs);
			} else {
				// warn the user and don't allow the insert
			}

		}

		@Override
		public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
			Document doc = fb.getDocument();
			StringBuilder sb = new StringBuilder();
			sb.append(doc.getText(0, doc.getLength()));
			sb.delete(offset, offset + length);

			if (test(sb.toString())) {
				super.remove(fb, offset, length);
			} else {
				// warn the user and don't allow the insert
			}
		}
	}
}