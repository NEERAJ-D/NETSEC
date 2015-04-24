package com.netsec.firewall;

import java.util.Map;

public class Requests {

	private Map<String, Payload> requests;

	public Map<String, Payload> getRequests() {
		return requests;
	}

	public void setRequests(Map<String, Payload> requests) {
		this.requests = requests;
	}
}
