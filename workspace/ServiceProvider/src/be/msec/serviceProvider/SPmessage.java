package be.msec.serviceProvider;

import java.io.Serializable;

/**
 * Simple sendable message that can contain any data, and uses an Enum as type identifier
 * @author Pedro
 *
 */
public class SPmessage implements Serializable {
	private static final long serialVersionUID = -2714228963872918578L;
	private SPmessageType msgType;
	private Object data;

	public SPmessage(SPmessageType msgType, Object data) {
		this.msgType = msgType;
		this.data = data;
	}
	public SPmessage(SPmessageType msgType) {
		this(msgType, null);
	}
	
	public SPmessageType getMessageType(){
		return this.msgType;
	}
	
	public Object getData(){
		return this.data;
	}
}

