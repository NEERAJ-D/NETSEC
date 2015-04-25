package com.netsec.firewall;

import java.util.*;
import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FilterRequests {

	private static final Logger logger = Logger.getLogger("FilteredRequests");
	public static List<String> properties = new ArrayList<String>();

	public static void learnsignatures() {

		try {
			File file = new File(WAFParameters.getSIGNATURE_FILE());
			FileReader fileReader = new FileReader(file);
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			String line;
			while ((line = bufferedReader.readLine()) != null) {
				properties.add(line);
			}
			fileReader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static boolean filterRequests(UserRequest request) {

		boolean sign = signaturefiltering(request.getHeader(),
				request.getParameters());
		if (!sign)
			return false;
		else {
			boolean profile = profilefiltering(request.getHeader(),
					request.getParameters());
			if (!profile)
				return false;
		}
		return true;
	}

	private static boolean signaturefiltering(Map<String, String> header,
			Map<String, String> parameters) {

		for (String property : properties) {
			String[] str = property.split(",");

			if (str[0].equals("")) {
				boolean checkresult = checksigunature(header, parameters, str);
				if (checkresult == false)
					return false;
			} else {
				if (header.get(FilterConstants.METHOD_TAG).equals(str[0])) {
					boolean checkresult = checksigunature(header, parameters,
							str);
					if (checkresult == false)
						return false;
				}
			}
		}
		return true;
	}

	public static boolean checksigunature(Map<String, String> header,
			Map<String, String> parameters, String[] str) {

		if (str[1].equals(FilterConstants.HEADER_TAG)) {
			if (str[2].equals("*")) {
				// iterate all of header and check str[3]
				for (Map.Entry<String, String> entry : header.entrySet()) {
					String value = entry.getValue();
					if (value.contains(str[3]))
						return false;
				}
			} else {
				if (header.get(str[2]) != null) {
					if (header.get(str[2]).contains(str[3]))
						return false;
				}
			}
		} else {
			if (str[2].equals("*")) {
				// iterate all of parameter and check str[3]
				for (Map.Entry<String, String> entry : parameters.entrySet()) {
					String value = entry.getValue();
					if (value.contains(str[3]))
						return false;
				}
			} else {
				if (parameters.get(str[2]) != null) {
					if (parameters.get(str[2]).contains(str[3]))
						return false;
				}
			}
		}
		return true;
	}

	private static boolean profilefiltering(Map<String, String> header,
			Map<String, String> parameters) {
		boolean head = filterHeader(header);
		if (head == false)
			return false;
		else {
			boolean param = filterParameters(parameters);
			if (param == false)
				return false;
		}
		return true;
	}

	public static boolean filterHeader(Map<String, String> header) {

		String url = header.get(FilterConstants.REFERER);
		Payload p = DataManager.getInstance().refererurlmap.get(url);

		int content_length = Integer.parseInt(header
				.get(FilterConstants.CONTENTLENGTH));

		if (content_length > p.header_data.validation_variable.max) {
			logger.log(Level.SEVERE, "Header Content Length exceeded the limit");
			return false;
		}
		if (content_length < p.header_data.validation_variable.min) {
			logger.log(Level.SEVERE, "Header Content Length under the limit");
			return false;
		}

		return true;
	}

	public static boolean filterParameters(Map<String, String> parameters) {

		int number;
		boolean temp = false;
		String url = parameters.get(FilterConstants.REFERER);
		Payload p = DataManager.getInstance().refererurlmap.get(url);

		if (parameters.size() != p.variables_data.size()) {
			logger.log(Level.SEVERE, "Incorrect number of Parameters");
			return false;
		}

		for (Map.Entry<String, ParameterVariables> entry : p.variables_data
				.entrySet()) {

			String key = entry.getKey();
			ParameterVariables value = entry.getValue();

			if (!parameters.containsKey(key)) {
				logger.log(Level.SEVERE, "Invalid Parameter");
				return false;
			}
			String req_value = parameters.get(key);

			temp = DataManager.getInstance().IsFieldNumeric(req_value);

			if (temp) {
				number = Integer.parseInt(req_value);
				if (number > value.validationrules.max) {
					logger.log(Level.SEVERE, "Value for " + key
							+ " exceeded the limit");
					return false;
				}
				if (number < value.validationrules.min) {
					logger.log(Level.SEVERE, "Value for " + key
							+ " under the limit");
					return false;
				}
			} else {
				number = req_value.length();
				if (number > value.validationrules.max) {
					logger.log(Level.SEVERE, "Content length for " + key
							+ " exceeded the limit");
					return false;
				}
				if (number < value.validationrules.min) {
					logger.log(Level.SEVERE, "Content length for " + key
							+ " under the limit");
					return false;
				}
			}

			if (temp != value.IsNumeric) {
				logger.log(Level.SEVERE,
						"Type mismatch : Numeric value expected");
				return false;
			}

			temp = DataManager.getInstance().IsFieldEmailID(req_value);
			if (temp != value.IsEmailID) {
				logger.log(Level.SEVERE, "Not an valid Email");
				return false;
			}

			temp = DataManager.getInstance().IsFieldAlphaNumeric(req_value);
			if (temp != value.IsAlphaNumeric) {
				logger.log(Level.SEVERE,
						"Type mismatch : Alpha Numeric value expected");
				return false;
			}

			temp = DataManager.getInstance().IsFieldAlphabet(req_value);
			if (temp != value.IsCharacter) {
				logger.log(Level.SEVERE,
						"Type mismatch : only Alphabets expected");
				return false;
			}
		}
		return true;
	}

}
