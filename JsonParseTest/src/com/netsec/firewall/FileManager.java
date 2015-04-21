package com.netsec.firewall;

import java.io.FileReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class FileManager {
	
	private static final String REQUESTS = "requests";
	//Parameter Section
	private static final String PARAMETERS = "parameters";
	
	//Header Section
	private static final String HEADER = "header";
	
	//Output File Constants
	private static final String MINIMUM_TAG  = "min";
	private static final String MAXIMUM_TAG  = "max";
	private static final String AVERAGE_TAG  = "average";
	
	//Header Section
	private static final String TOTAL_PARAMETERS_TAG  ="totalparameters";
	
	//Parameter Section
	private static final String ISEMAILID_TAG  ="is_email_id";
	private static final String ISNUMERIC_TAG  ="is_numeric";
	private static final String ISALPHABET_TAG  ="is_alphabet";
	private static final String ISALPHANUMERIC_TAG  ="is_alphanumeric";
	
	
	
	private static FileReader file_learning_input;
	FileManager ()
	{
		
	}

	public static void ParseAllRequests(JSONArray requests)
	{
		//A pointer to a single request
		Iterator singlerequest = requests.iterator();
		
		while (singlerequest.hasNext()) {
	        	
	        	//Single Request object
	            JSONObject request = (JSONObject) singlerequest.next();
	            //Parse a single request           
	            ParseRequest(request);
	            //Validate the Payload
	            DataManager.getInstance().ValidatePayload();
				//Separator print #DEBUG
	        	System.out.println("-------------------");
				}
	}
	private static void ParseRequest(JSONObject request)
	{
		try
		{
		
			DataManager.getInstance().current_header = new JSONObject();
			DataManager.getInstance().current_parameters = new JSONObject();
			
	        //Header of request
			DataManager.getInstance().current_header = (JSONObject) request.get(HEADER);			
	        
	        //Parameter section of request
			DataManager.getInstance().current_parameters = (JSONObject) request.get(PARAMETERS);
			}
			catch (NullPointerException ex) {
				ex.printStackTrace();
			}
	}
	
	private String ReadFromJSONObject(JSONObject obj,String param)
	 {
		   return (String) obj.get(param);
	 }
	
	public static void InitializeLearningInput(String FILEPATH)
	{
		try
		{
			// read the json file
			file_learning_input = new FileReader(FILEPATH);
		}
		catch (FileNotFoundException ex) {
			ex.printStackTrace();
		}
	
	}
	public static JSONArray ReadLearningInput()
	{
		JSONArray requests = null;
		try
		{
			JSONParser jsonParser = new JSONParser();
			JSONObject jsonObject = (JSONObject) jsonParser.parse(file_learning_input);
		
			//All the requests in the input log file
			requests = (JSONArray) jsonObject.get(REQUESTS);
			
			
		}
		
		catch (IOException ex) {
			ex.printStackTrace();
		} catch(ParseException ex)
		{
			ex.printStackTrace();
		}catch (NullPointerException ex) {
			ex.printStackTrace();
		}
		return requests;
	}
	private static void WriteHeader(JSONObject ObjHeaderInfo,HeaderInfo header_info)
	{
       	ObjHeaderInfo.put(MAXIMUM_TAG, header_info.validation_variable.max);
		ObjHeaderInfo.put(MINIMUM_TAG, header_info.validation_variable.min);
		ObjHeaderInfo.put(AVERAGE_TAG, header_info.validation_variable.average);
		ObjHeaderInfo.put(TOTAL_PARAMETERS_TAG, header_info.totalrequests);
	}
	
	
	private static void WriteParameter(JSONArray ParameterArray,HashMap<String,ParameterVariables> parameter_variables_data)
	{
    	Iterator<Map.Entry <String, ParameterVariables>> parameter_value_map = parameter_variables_data.entrySet().iterator();
    	
    	while(parameter_value_map.hasNext())
    	{
    		Map.Entry <String, ParameterVariables> single_parameter_iterator = parameter_value_map.next();
    		
    		//Get the parameter variables
    		String parameter_name = single_parameter_iterator.getKey();
    		ParameterVariables parameter_value = single_parameter_iterator.getValue();
    		
    		JSONObject ParameterInfo = new JSONObject();
    		JSONObject ParameterData = new JSONObject();
    		
    		//Iterate all the parameters
    		ParameterData.put(MAXIMUM_TAG, parameter_value.validationrules.max );
    		ParameterData.put(MINIMUM_TAG, parameter_value.validationrules.min);
    		ParameterData.put(AVERAGE_TAG,parameter_value.validationrules.average );
        	
    		//Write boolean values
    		ParameterData.put(ISEMAILID_TAG, parameter_value.IsEmailID );
    		ParameterData.put(ISNUMERIC_TAG, parameter_value.IsNumeric );
    		ParameterData.put(ISALPHANUMERIC_TAG, parameter_value.IsEmailID );
    		ParameterData.put(ISALPHABET_TAG, parameter_value.IsCharacter );
        	
        	ParameterInfo.put(parameter_name,ParameterData );
        	
        	//Add parameter to the parameter array
        	ParameterArray.add(ParameterInfo);
    	}
    	
	}
	
	public static void WriteOutputFile()
	{
		try
		{
        Iterator<Map.Entry <String, Payload>> refererurllist = DataManager.getInstance().refererurlmap.entrySet().iterator();
        /* Iterate the HashMap and print contents */
        System.out.println("Printing map contents to JSON File");   
        JSONObject jsonParameterData = new JSONObject(DataManager.getInstance().refererurlmap);
        JSONArray jsonArrayOfRequest = new JSONArray();
        while (refererurllist.hasNext()) {
        	
        	Map.Entry <String, Payload> entry = refererurllist.next();
        	
        	//Get the URL and the payload associated with the URL
        	String refererurl = entry.getKey();
        	Payload temp = (Payload)entry.getValue();
        	
        	//Write Header Information
        	JSONObject ObjHeaderInfo = new JSONObject();
        	WriteHeader(ObjHeaderInfo,temp.header_data);
        		        	
  	        //Write Parameter Information        	
        	JSONArray ParameterArray = new JSONArray();
        	WriteParameter(ParameterArray,temp.variables_data);

        	//Write the Payload Information
        	JSONObject PayloadInfo = new JSONObject();
        	PayloadInfo.put(HEADER, ObjHeaderInfo);
        	PayloadInfo.put(PARAMETERS, ParameterArray);
        	jsonParameterData.put(refererurl, PayloadInfo);
        	
        	//Add the parameter in the Arraylist of requests
        	jsonArrayOfRequest.add(jsonParameterData)  ;    	       	
            //System.out.println("Key = " + entry.getKey() + ", Value = " + temp.genericinfo.content_length_average);
        	
        }//After all the requests have been iterated
        
        JSONObject outputrequests = new JSONObject();
        outputrequests.put(REQUESTS,jsonArrayOfRequest );
        	        
        /* File writing Logic */
        FileWriter file = new FileWriter("D:\\Study\\Network Security\\modelfile.json");
        file.write(outputrequests.toJSONString());  
        System.out.println("Successfully Copied JSON Object to File...");
        System.out.println("\nJSON Object: " + jsonParameterData);
        file.flush();
        file.close();
        
	} catch (FileNotFoundException ex) {
		ex.printStackTrace();
	} catch (IOException ex) {
		ex.printStackTrace();
	} catch (NullPointerException ex) {
		ex.printStackTrace();
	}
	}
	
	

}
