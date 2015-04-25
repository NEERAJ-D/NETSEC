package com.netsec.firewall;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

public class FilterRequests {

	private static final Logger logger = Logger.getLogger("NETSEC");
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

		if (DataManager.getInstance().refererurlmap == null
				|| DataManager.getInstance().refererurlmap.size() == 0) {
			ModelReader md = new ModelReader();
			md.generateModel();
		}
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
			boolean param = filterParameters(parameters, header);
			if (param == false)
				return false;
		}
		return true;
	}

	public static boolean filterHeader(Map<String, String> header) {
		/*logger.log(Level.WARNING, "Header  : " + header.toString());
		String url = header.get(FilterConstants.REFERER);
		Payload p = DataManager.getInstance().refererurlmap.get(url);
		if (p != null && header.containsKey(FilterConstants.CONTENTLENGTH)) {
			int content_length = Integer.parseInt(header
					.get(FilterConstants.CONTENTLENGTH));

			if (content_length > p.header_data.validation_variable.max) {
				logger.log(Level.SEVERE,
						"Header Content Length exceeded the limit");
				return false;
			}
			if (content_length < p.header_data.validation_variable.min) {
				logger.log(Level.SEVERE,
						"Header Content Length under the limit");
				return false;
			}
		}*/
		return true;
	}

	public static boolean filterParameters(Map<String, String> parameters,Map<String, String> header) {

		int number;
		boolean temp = false;
		logger.warn("Parameters  : " + parameters.toString());
		String url = header.get(FilterConstants.REFERER);
		Payload p = DataManager.getInstance().refererurlmap.get(url);
		logger.warn("Payload  : " + DataManager.getInstance().refererurlmap);
		if (p != null) {
			if (parameters.size() != p.variables_data.size()) {
				logger.warn("Incorrect number of Parameters");
				return false;
			}

			for (Map.Entry<String, ParameterVariables> entry : p.variables_data
					.entrySet()) {

				String key = entry.getKey();
				ParameterVariables value = entry.getValue();
				
				if (!(DataManager.getInstance().IsFieldFile(key))) {
					if (!parameters.containsKey(key)) {
						logger.warn( "Invalid Parameter");
						return false;
					}
					String req_value = parameters.get(key);
					logger.warn( "Value for " + key
							+ "is" + req_value+" : "+value.toString());
					double std_dev = p.variables_data.get(key).validationrules.standard_deviation;
					int avg = p.variables_data.get(key).validationrules.average;

					temp = DataManager.getInstance().IsFieldNumeric(req_value);

					if (temp) {
						number = Integer.parseInt(req_value);
						if (number > value.validationrules.max) {
							logger.warn("Value for " + key
									+ " exceeded the limit");
							return false;
						}
						if (number < value.validationrules.min) {
							logger.warn("Value for " + key
									+ " under the limit");
							return false;
						}
						if ((avg - std_dev) > number
								|| number > (avg + std_dev)) {
							logger.warn("Value for " + key
									+ " is out of bound");
							return false;
						}

					} else {
						number = req_value.length();
						if (number > value.validationrules.max) {
							logger.warn("Content length for "
									+ key + " exceeded the limit");
							return false;
						}
						if (number < value.validationrules.min) {
							logger.warn("Content length for "
									+ key + " under the limit");
							return false;
						}
						if ((avg - std_dev) > number
								|| number > (avg + std_dev)) {
							logger.warn("Content Length for "
									+ key + " is out of bound");
							return false;
						}

					}

					if (temp != value.IsNumeric) {
						logger.warn(
								"Type mismatch : Numeric value expected");
						return false;
					}

					temp = DataManager.getInstance().IsFieldEmailID(req_value);
					if (temp != value.IsEmailID) {
						logger.warn("Not an valid Email");
						return false;
					}

					temp = DataManager.getInstance().IsFieldAlphaNumeric(
							req_value);
					if (temp != value.IsAlphaNumeric) {
						logger.warn(
								"Type mismatch : Alpha Numeric value expected");
						return false;
					}

					temp = DataManager.getInstance().IsFieldAlphabet(req_value);
					if (temp != value.IsCharacter) {
						logger.warn("Type mismatch : only Alphabets expected");
						return false;
					}
				}
			}
		} else {
			return parameters.size() <= DataManager.getInstance().maximum_number_of_parameters;
		}
		return true;
	}

}
