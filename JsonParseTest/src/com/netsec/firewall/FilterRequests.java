package com.netsec.firewall;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;

public class FilterRequests {

	private static final Logger logger = Logger.getLogger("NETSEC");
	public static List<String> properties = new ArrayList<String>();

	public static void learnsignatures() {
		//Reads the signatures from signature file and store in list
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

		// Request received for filtering
		if (DataManager.getInstance().refererurlmap == null
				|| DataManager.getInstance().refererurlmap.size() == 0) {
			//If no learning data present read it from model file
			ModelReader md = new ModelReader();
			md.generateModel();
		}
		//Signature filtering 
		boolean sign = signaturefiltering(request.getHeader(),
				request.getParameters());
		if (!sign)
			return false;
		else {
			//Profile filtering
			boolean profile = profilefiltering(request.getHeader(),
					request.getParameters());
			if (!profile)
				return false;
		}
		return true;
	}

	private static boolean signaturefiltering(Map<String, String> header,
			Map<String, String> parameters) {
		//check if signatures are loaded otherwise read it from file
		if (properties.size() == 0) {
			learnsignatures();
		}
		for (String property : properties) {
			String[] str = property.split(",");
			//For each signature check with the received request
			if (str[0].equals("")) {
				boolean checkresult = checksigunature(header, parameters, str);
				if (checkresult == false) {
					logger.error("Blocked due to signature match :" + property
							+ " Values :" + header);
					return false;
				}
			} else {
				if (header.get(FilterConstants.METHOD).equals(str[0])) {
					boolean checkresult = checksigunature(header, parameters,
							str);
					if (checkresult == false) {
						logger.error("Blocked due to signature match :"
								+ property + " Values :" + parameters);
						return false;
					}
				}
			}
		}
		return true;
	}

	public static boolean checksigunature(Map<String, String> header,
			Map<String, String> parameters, String[] str) {

		if (str[1].equals(FilterConstants.HEADER_TAG)) {
			if (str[2].equals("*")) {
				// checks the signature for all the fields in header
				for (Map.Entry<String, String> entry : header.entrySet()) {
					String value = entry.getValue();
					if (value.contains(str[3]))
						return false;
				}
			} else {
				//check signature for specified field in header
				if (header.get(str[2]) != null) {
					if (header.get(str[2]).contains(str[3]))
						return false;
				}
			}
		} else {
			Pattern pattern_fp = Pattern.compile(FilterConstants.regex_file_path, Pattern.CASE_INSENSITIVE| Pattern.DOTALL);
			if (str[2].equals("*")) {
				// checks the signature for all the fields in parameter

				for (Map.Entry<String, String> entry : parameters.entrySet()) {
				String value = entry.getValue();
				if(str[3].equals(FilterConstants.FILE_PATH)){
					Matcher m = pattern_fp.matcher(value);
				    if (m.find())
				    {
				    	return false;
				    }
				}
				else if (value.contains(str[3]))
						return false;
				}
			} else {
				//check signature for specified field in parameter
				if (parameters.get(str[2]) != null) {
					if(str[3].equals(FilterConstants.FILE_PATH)){
						logger.warn("Inside regex path");
						Matcher m = pattern_fp.matcher(parameters.get(str[2]));
					    if (m.find())
					    {
					    	return false;
					    }
					}
					else if (parameters.get(str[2]).contains(str[3]))
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
		/*
		 * logger.log(Level.WARNING, "Header  : " + header.toString()); String
		 * url = header.get(FilterConstants.REFERER); Payload p =
		 * DataManager.getInstance().refererurlmap.get(url); if (p != null &&
		 * header.containsKey(FilterConstants.CONTENTLENGTH)) { int
		 * content_length = Integer.parseInt(header
		 * .get(FilterConstants.CONTENTLENGTH));
		 * 
		 * if (content_length > p.header_data.validation_variable.max) {
		 * logger.log(Level.SEVERE, "Header Content Length exceeded the limit");
		 * return false; } if (content_length <
		 * p.header_data.validation_variable.min) { logger.log(Level.SEVERE,
		 * "Header Content Length under the limit"); return false; } }
		 */
		return true;
	}

	public static boolean filterParameters(Map<String, String> parameters,
			Map<String, String> header) {
		//Filtering parameters 
		int number;
		boolean temp = false;
		String url = header.get(FilterConstants.REFERER);
		Payload p = DataManager.getInstance().refererurlmap.get(url);
		logger.warn("Payload  : " + DataManager.getInstance().refererurlmap);
		if (p != null) {
			if (parameters.size() != p.variables_data.size()) {
				//check if number of parameters in request and in model are equal
				logger.warn("Incorrect number of Parameters");
				return false;
			}

			for (Map.Entry<String, ParameterVariables> entry : p.variables_data
					.entrySet()) {
				//For each parameter in model compare the values 
				String key = entry.getKey();
				ParameterVariables value = entry.getValue();
				if (!parameters.containsKey(key)) {
					logger.warn("Invalid Parameter");
					return false;
				}
				String req_value = parameters.get(key);
				//check if parameter is of file type
				if (value.IsFile) {
					if (!DataManager.getInstance().IsFieldFile(req_value)) {
						logger.warn("Invalid File type : " + req_value);
						return false;
					}
				} else {

					double std_dev = p.variables_data.get(key).validationrules.standard_deviation;
					int avg = (int)p.variables_data.get(key).validationrules.average;
					temp = DataManager.getInstance().IsFieldEmailID(req_value);
					if (temp != value.IsEmailID) {
						logger.warn("Not an valid Email");
						return false;
					}

					boolean numericField = DataManager.getInstance()
							.IsFieldNumeric(req_value);
					boolean characterField = DataManager.getInstance()
							.IsFieldAlphabet(req_value);
					if (value.IsNumeric && value.IsCharacter) {
						if (!(numericField || characterField)) {
							return false;
						}
					} else if (value.IsNumeric
							&& (!numericField || characterField)) {
						logger.warn("Type mismatch : Numeric value expected "
								+ key + ":" + req_value);
						return false;
					} else if (value.IsCharacter
							&& (!characterField || numericField)) {
						logger.warn("Type mismatch : only Alphabets expected "
								+ key + ":" + req_value);
						return false;
					}
					
					
					temp = DataManager.getInstance().IsFieldEntireNumeric(
							req_value);

					if (temp) {
						
						number = Integer.parseInt(req_value);
						if (number > value.validationrules.max) {
							logger.warn("Value for " + key
									+ " exceeded the limit");
							return false;
						}
						if (number < value.validationrules.min) {
							logger.warn("Value for " + key + " under the limit");
							return false;
						}
						if ((avg -  (3 * std_dev)) > number
								|| number > (avg + (3 *std_dev))) {
							logger.warn("Value for " + key + " is out of bound");
							return false;
						}

					} else {
						number = req_value.length();
						if (number > value.validationrules.max) {
							logger.warn("Content length for " + key
									+ " exceeded the limit");
							return false;
						}
						if (number < value.validationrules.min) {
							logger.warn("Content length for " + key
									+ " under the limit");
							return false;
						}
						if ((avg - std_dev) > number
								|| number > (avg + std_dev)) {
							logger.warn("Content Length for " + key
									+ " is out of bound");
							return false;
						}

					}

				}
			}
		} else {
			return parameters.size() <= DataManager.getInstance().maximum_number_of_parameters;
		}
		return true;
	}

}
