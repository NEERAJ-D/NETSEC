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

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		JSONParser parser = new JSONParser();
		String input_file_path = "modelfile.json";
		HashMap<String,Payload> refererurlmap = new HashMap<String,Payload>();
		//HashMap<String,HeaderInfo> ParameterVariables;
		try {
			JSONObject obj = (JSONObject)parser.parse(new FileReader(input_file_path));
			int max_number_of_parameters = Integer.parseInt(obj.get("maximum_number_of_paramteres").toString());
			
			System.out.println(max_number_of_parameters);
			
			JSONArray jsonArrayOfRequest = (JSONArray) obj.get("requests");
			for (int i = 0; i < jsonArrayOfRequest.size(); i++)
			{
			JSONObject obj2 = (JSONObject) jsonArrayOfRequest.get(i);
			
				//System.out.println(obj2);
				for (Object key : obj2.keySet()) {
					//String key = keys.toString();
					//System.out.println(key);
					JSONObject payload = (JSONObject) obj2.get(key);
					//System.out.println(payload);
					JSONArray parameters = (JSONArray) payload.get("parameters");
					JSONObject header = (JSONObject) payload.get("header");
					//System.out.println(parameters);
					//System.out.println(header);
					Payload p = new Payload();
					p.header_data.validation_variable.max = Integer.parseInt(header.get("max").toString());//fill
					p.header_data.validation_variable.average = Integer.parseInt(header.get("average").toString());
					p.header_data.validation_variable.min = Integer.parseInt(header.get("min").toString());
					/*public VariableValidation() {
		max = 0;
		average = 0;
		min = Integer.MAX_VALUE;
		dataType = "";
	}*/		
							
					p.header_data.total_number_of_variables = header.size();
					p.header_data.user_agent = "";
					p.header_data.method = (String) header.get("METHOD");
					/*
					 * HeaderInfo ()
		{
			validation_variable = new VariableValidation();
			total_number_of_variables  = 0;
			user_agent = "";
			method = "";
		}
					 * */
					for(int j=0;j<parameters.size();j++)
					{	
					//System.out.println(parameters.get(i));
						JSONObject param = (JSONObject)parameters.get(j);
						//System.out.println(param);
						String par_name="";
						for (Object k : param.keySet()) 
						{
							par_name = k.toString();//param.get(k).toString();
							break;
						
						}
						//System.out.println(par_name);
						JSONObject param_details = (JSONObject) param.get(par_name);
						//System.out.println(param_details);
						ParameterVariables PV = new ParameterVariables();
						PV.IsEmailID = (boolean) param_details.get("is_email_id");
						PV.IsNumeric = (boolean) param_details.get("is_numeric");
						PV.IsAlphaNumeric = (boolean) param_details.get("is_alphanumeric");
						PV.IsCharacter = (boolean) param_details.get("is_alphabet");
						PV.validationrules.average = Integer.parseInt( param_details.get("average").toString());
						PV.validationrules.max = Integer.parseInt(param_details.get("max").toString());
						PV.validationrules.min = Integer.parseInt(param_details.get("min").toString());
						PV.validationrules.standard_deviation = Double.parseDouble(param_details.get("standard_deviation").toString());
						
						
						
						
						p.variables_data.put(par_name,PV);//fill
						
					
					}
					//System.out.println(max_number_of_parameters);
					refererurlmap.put(key.toString(), p);
					System.out.println(key);
					System.out.println(p);
					System.out.println();
					
					
					//public HashMap<String,ParameterVariables> variables_data = null;
					/*public class ParameterVariables {
	
	ArrayList<String> parameterValues;
	ArrayList<Integer> listofcontentlengths;
	VariableValidation validationrules;
	int numberofinstances;
	boolean IsEmailID;
	boolean IsNumeric;
	boolean IsAlphaNumeric;
	boolean IsCharacter;
	boolean IsFile;
	
}
*/
					
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
			
	}

}
