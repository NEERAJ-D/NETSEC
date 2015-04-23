package com.netsec.firewall;

import java.util.HashMap;
import java.util.Map;

public class UserRequest {

	private Map<String, String> header = new HashMap<String, String>();
	private Map<String, String> parameters = new HashMap<String, String>();

	public Map<String, String> getHeader() {
		return header;
	}

	public void setHeader(Map<String, String> header) {
		this.header = header;
	}

	public Map<String, String> getParameters() {
		return parameters;
	}

	public void setParameters(Map<String, String> parameters) {
		this.parameters = parameters;
	}
	
}
