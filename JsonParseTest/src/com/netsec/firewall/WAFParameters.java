package com.netsec.firewall;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

public class WAFParameters implements FileChangeListener {
	public static Properties CONFIG_FILE_PATHS = new Properties();
	private static WAFParameters instance;
	private static String SIGNATURE_FILE;
	private static String MODEL_FILE;
	private static String LOG_FILE;
	private static String propertyHome = System.getenv("CATALINA_HOME");

	protected WAFParameters() throws FileNotFoundException {
		loadProperties();
		FileMonitor.getInstance().addFileChangeListener(
				this,
				propertyHome + File.separatorChar
						+ "properties/files.properties", 5000);
	}

	public static String getSIGNATURE_FILE() {
		return SIGNATURE_FILE;
	}

	public static void setSIGNATURE_FILE(String sIGNATURE_FILE) {
		SIGNATURE_FILE = sIGNATURE_FILE;
	}

	public static String getMODEL_FILE() {
		return MODEL_FILE;
	}

	public static void setMODEL_FILE(String mODEL_FILE) {
		MODEL_FILE = mODEL_FILE;
	}

	public static String getLOG_FILE() {
		return LOG_FILE;
	}

	public static void setLOG_FILE(String lOG_FILE) {
		LOG_FILE = lOG_FILE;
	}

	public static WAFParameters getInstance() throws FileNotFoundException {
		if (instance == null) {
			instance = new WAFParameters();
		}
		System.out.println(instance.toString());
		return instance;
	}

	public static void loadProperties() {

		try {
			CONFIG_FILE_PATHS.load(new FileReader(propertyHome
					+ File.separatorChar + "properties/files.properties"));
			String modelFile = CONFIG_FILE_PATHS.getProperty("modelFile");
			String logFile = CONFIG_FILE_PATHS.getProperty("logFile");
			String signaturesFile = CONFIG_FILE_PATHS
					.getProperty("signaturesFile");
			if (modelFile != null) {
				setMODEL_FILE(propertyHome + modelFile);
			}
			if (logFile != null) {
				setLOG_FILE(propertyHome + logFile);
			}
			if (signaturesFile != null) {
				setSIGNATURE_FILE(propertyHome + signaturesFile);
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return getLOG_FILE() + "|" + getMODEL_FILE() + "|"
				+ getSIGNATURE_FILE();
	}

	@Override
	public void fileChanged(String fileName) {
		loadProperties();

	}
}
