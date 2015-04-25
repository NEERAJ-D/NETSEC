package com.netsec.firewall;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class ModelReader {

	public static HashMap<String, Payload> generateModel() {
		JSONParser parser = new JSONParser();
		String input_file_path = WAFParameters.getMODEL_FILE();
		HashMap<String, Payload> refererurlmap = new HashMap<String, Payload>();
		try {
			JSONObject obj = (JSONObject) parser.parse(new FileReader(
					input_file_path));
			int max_number_of_parameters = Integer.parseInt(obj.get(
					FilterConstants.MAX_PARAMETERS).toString());

			System.out.println(max_number_of_parameters);

			JSONArray jsonArrayOfRequest = (JSONArray) obj.get(FilterConstants.REQUESTS);
			for (int i = 0; i < jsonArrayOfRequest.size(); i++) {
				JSONObject obj2 = (JSONObject) jsonArrayOfRequest.get(i);
				for (Object key : obj2.keySet()) {
					JSONObject payload = (JSONObject) obj2.get(key);
					JSONArray parameters = (JSONArray) payload
							.get(FilterConstants.PARAMETERS);
					JSONObject header = (JSONObject) payload.get(FilterConstants.HEADER);
					Payload p = new Payload();
					p.header_data.validation_variable.max = Integer
							.parseInt(header.get(FilterConstants.MAXIMUM_TAG).toString());// fill
					p.header_data.validation_variable.average = Integer
							.parseInt(header.get("average").toString());
					p.header_data.validation_variable.min = Integer
							.parseInt(header.get("min").toString());

					p.header_data.total_number_of_variables = header.size();
					p.header_data.user_agent = "";
					p.header_data.method = (String) header
							.get(FilterConstants.METHOD_TAG);
					for (int j = 0; j < parameters.size(); j++) {
						JSONObject param = (JSONObject) parameters.get(j);
						String par_name = "";
						for (Object k : param.keySet()) {
							par_name = k.toString();// param.get(k).toString();
							break;

						}
						JSONObject param_details = (JSONObject) param
								.get(par_name);

						ParameterVariables PV = new ParameterVariables();
						PV.IsEmailID = (boolean) param_details
								.get(FilterConstants.ISEMAILID_TAG);
						PV.IsNumeric = (boolean) param_details
								.get(FilterConstants.ISNUMERIC_TAG);
						PV.IsAlphaNumeric = (boolean) param_details
								.get(FilterConstants.ISALPHANUMERIC_TAG);
						PV.IsCharacter = (boolean) param_details
								.get(FilterConstants.ISALPHABET_TAG);
						PV.validationrules.average = Integer
								.parseInt(param_details.get(
										FilterConstants.AVERAGE_TAG).toString());
						PV.validationrules.max = Integer.parseInt(param_details
								.get(FilterConstants.MAXIMUM_TAG).toString());
						PV.validationrules.min = Integer.parseInt(param_details
								.get(FilterConstants.MINIMUM_TAG).toString());
						PV.validationrules.standard_deviation = Double
								.parseDouble(param_details.get(
										FilterConstants.STANDARD_DEVIATION_TAG)
										.toString());
						p.variables_data.put(par_name, PV);// fill

					}
					refererurlmap.put(key.toString(), p);
				}

			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return refererurlmap;
	}

}
