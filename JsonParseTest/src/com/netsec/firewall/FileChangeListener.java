package com.netsec.firewall;

/**
 * Interface called after every 5000 milli-seconds
 * @author nikhil
 *
 */
public interface FileChangeListener {
	 public void fileChanged(String fileName);
}
