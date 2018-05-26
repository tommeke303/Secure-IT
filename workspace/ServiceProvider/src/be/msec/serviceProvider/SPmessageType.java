package be.msec.serviceProvider;

/**
 * CLOSE: This connection will be closed
 * SP_CERTIFICATE: The certificate of the service provider is sent
 * AUTH_SP: Authentication message to authenticate the SP
 * AUTH_CARD: Authentication message to authenticate the javacard
 * 
 * @author Pedro
 *
 */
public enum SPmessageType{
	CLOSE,
	SP_CERTIFICATE,
	AUTH_SP,
	AUTH_CARD
}
