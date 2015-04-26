package com.netsec.firewall;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;

//import java.util.logging.Logger;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;


public class ModelReader {

	private static final Logger logger = Logger.getLogger("NETSEC");
	//public static void main(String[] args)
	//{

	
	
	public static void generateModel() {
		JSONParser parser = new JSONParser();
		String input_file_path = WAFParameters.getMODEL_FILE();//"modelfile.json";
		HashMap<String, Payload> refererurlmap = new HashMap<String, Payload>();
		int max_number_of_parameters = 0;
		Payload p;
		//logger.log(Level.WARNING, "Parameters  : " + parameters.toString());
		logger.warn("ModelReader starting to read model");
		
		try {
			JSONObject obj = (JSONObject) parser.parse(new FileReader(
					input_file_path));
			max_number_of_parameters = Integer.parseInt(obj.get(
					FilterConstants.MAX_PARAMETERS).toString());

			JSONArray jsonArrayOfRequest = (JSONArray) obj.get(FilterConstants.REQUESTS);
			for (int i = 0; i < jsonArrayOfRequest.size(); i++) {
				JSONObject obj2 = (JSONObject) jsonArrayOfRequest.get(i);
				for (Object key : obj2.keySet()) {
					JSONObject payload = (JSONObject) obj2.get(key);
					JSONArray parameters = (JSONArray) payload
							.get(FilterConstants.PARAMETERS);
					JSONObject header = (JSONObject) payload.get(FilterConstants.HEADER);
					p = new Payload();
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
		DataManager.getInstance().setmap(refererurlmap);
		DataManager.getInstance().setmaxparameters(max_number_of_parameters);
		//::test code
		/*
		System.out.println(DataManager.getInstance().maximum_number_of_parameters);
		
		System.out.println(DataManager.getInstance().refererurlmap.size());
		for (Object key : DataManager.getInstance().refererurlmap.keySet())
		{
			System.out.println(key.toString());
			System.out.println(DataManager.getInstance().refererurlmap.get(key.toString()).variables_data);
		
			
		}
		*/
		
		logger.warn("ModelReader finished reading the model.");
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
		catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			logger.error("",e);
		}
	}

//}//end main
}
