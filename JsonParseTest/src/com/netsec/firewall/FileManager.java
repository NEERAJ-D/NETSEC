package com.netsec.firewall;

import java.io.BufferedReader;
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
	

	
	//File Operations Objects
	private static FileReader file_learning_input;
	private static BufferedReader file_buffered_reader;
	private static JSONParser jsonParser;
	
	FileManager ()
	{
		
	}

	/*****************************************************************************
	Function Name:ParseAllRequests
	Function Parameters:None
	Function Description:Function that parses all the requests from JSON File
	*****************************************************************************/
	public static void ParseAllRequests() throws IOException, ParseException
	{
		//A pointer to a single request
		//Iterator singlerequest = requests.iterator();
		
		//JSON String that reads a single line of input
		String jsonString="";
		
		while ((jsonString=file_buffered_reader.readLine())!=null) {
	        	
	        	//Single Request object
	            //JSONObject request = (JSONObject) singlerequest.next();
				JSONObject jsonSingleRequest = (JSONObject) jsonParser.parse(jsonString);
			
	            //Parse a single request           
	            ParseRequest(jsonSingleRequest);
	            
	            //Validate the Payload
	            DataManager.getInstance().ValidatePayload();
				
	            //Separator print #DEBUG
	        	System.out.println("-------------------");
				}
		
		//Standard deviation calculation
		PostProcessing();
		
	}
	/*****************************************************************************
	Function Name:PostProcessing
	Function Parameters:None
	Function Description:Function that updates the standard deviation
	*****************************************************************************/
	private static void PostProcessing()
	{
		//Processing for standard deviation
		
		DataManager.getInstance().refererurlmap.entrySet().iterator();
		
		//Iterate the map for each URL each parameter
		Iterator<Map.Entry <String, Payload>> RefererPayload = DataManager.getInstance().refererurlmap.entrySet().iterator();
 		
		double standard_deviation = 0;
		int totalnumberofvariablevalues = 0;
		int maximum_number_of_parameters = 0;
    	while(RefererPayload.hasNext())
    	{
    		Map.Entry <String, Payload> single_payload = RefererPayload.next();
    		
    		Iterator<Map.Entry <String,ParameterVariables>> mapsinglepageparameter =  single_payload.getValue().variables_data.entrySet().iterator();
    		
    		while(mapsinglepageparameter.hasNext())
    		{
    			Map.Entry <String,ParameterVariables> singlepage_paramter_value = mapsinglepageparameter.next();
    			
    			totalnumberofvariablevalues = singlepage_paramter_value.getValue().listofcontentlengths.size();
    			
    			
    			for( Integer singlelement : singlepage_paramter_value.getValue().listofcontentlengths)
    			{
    				   				
    				//Calculate abs(individual - mean)
    				standard_deviation = standard_deviation + Math.pow(singlelement - singlepage_paramter_value.getValue().validationrules.average  , 2);
    				
    			}
    			double sd = Math.sqrt(standard_deviation/(totalnumberofvariablevalues));
    			
    			//Need to write the standard deviation sd to the file
    	    	singlepage_paramter_value.getValue().validationrules.standard_deviation = sd;
    	 
    	    	
    		}
    		//Find the maximum number of parameters all pages
    		if(maximum_number_of_parameters < single_payload.getValue().header_data.total_number_of_variables)
    			maximum_number_of_parameters = single_payload.getValue().header_data.total_number_of_variables;
    	}
    	DataManager.getInstance().maximum_number_of_parameters = maximum_number_of_parameters;
  
	}
	
	/*****************************************************************************
	Function Name:ParseRequest
	Function Parameters:JSONObject request
	Function Description:Function that parses each request
	*****************************************************************************/
	private static void ParseRequest(JSONObject request)
	{
		try
		{
		
			DataManager.getInstance().current_header = new JSONObject();
			DataManager.getInstance().current_parameters = new JSONObject();
			
	        //Header of request
			DataManager.getInstance().current_header = (JSONObject) request.get(FilterConstants.HEADER);			
	        
	        //Parameter section of request
			DataManager.getInstance().current_parameters = (JSONObject) request.get(FilterConstants.PARAMETERS);
			}
			catch (NullPointerException ex) {
				ex.printStackTrace();
			}
	}
	/*****************************************************************************
	Function Name:ReadFromJSONObject
	Function Parameters:JSONObject obj,String param
	Function Description:Function that reads from given JSON object
	*****************************************************************************/
	private String ReadFromJSONObject(JSONObject obj,String param)
	 {
		   return (String) obj.get(param);
	 }
	/*****************************************************************************
	Function Name:InitializeLearningInput
	Function Parameters:String FILEPATH
	Function Description:Function that initializes the file reader for input
	*****************************************************************************/
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
	
	/*****************************************************************************
	Function Name:ReadLearningInput
	Function Parameters:String FILEPATH
	Function Description:Function that initializes the file reader for input
	*****************************************************************************/
	public static void ReadLearningInput()
	{
		try
		{
			jsonParser = new JSONParser();
			file_buffered_reader = new BufferedReader(file_learning_input);
		}
		
		catch (NullPointerException ex) {
			ex.printStackTrace();
		}
		
	}
	/*****************************************************************************
	Function Name:WriteHeader
	Function Parameters:JSONObject ObjHeaderInfo,HeaderInfo header_info
	Function Description:Function that writes the Header
	*****************************************************************************/
	private static void WriteHeader(JSONObject ObjHeaderInfo,HeaderInfo header_info)
	{
       	ObjHeaderInfo.put(FilterConstants.MAXIMUM_TAG, header_info.validation_variable.max);
		ObjHeaderInfo.put(FilterConstants.MINIMUM_TAG, header_info.validation_variable.min);
		ObjHeaderInfo.put(FilterConstants.AVERAGE_TAG, header_info.validation_variable.average);
		ObjHeaderInfo.put(FilterConstants.TOTAL_PARAMETERS_TAG, header_info.totalrequests);
		ObjHeaderInfo.put(FilterConstants.METHOD_TAG, header_info.method);
	}
	
	/*****************************************************************************
	Function Name:WriteParameter
	Function Parameters:JSONArray ParameterArray, Map of Variable Name , Variable Data
	Function Description:Function that writes the Parameters learnt
	*****************************************************************************/
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
    		ParameterData.put(FilterConstants.MAXIMUM_TAG, parameter_value.validationrules.max );
    		ParameterData.put(FilterConstants.MINIMUM_TAG, parameter_value.validationrules.min);
    		ParameterData.put(FilterConstants.AVERAGE_TAG,parameter_value.validationrules.average );
    		ParameterData.put(FilterConstants.STANDARD_DEVIATION_TAG, parameter_value.validationrules.standard_deviation);
        	
    		//Write boolean values
    		ParameterData.put(FilterConstants.ISEMAILID_TAG, parameter_value.IsEmailID );
    		ParameterData.put(FilterConstants.ISNUMERIC_TAG, parameter_value.IsNumeric );
    		ParameterData.put(FilterConstants.ISALPHANUMERIC_TAG, parameter_value.IsEmailID );
    		ParameterData.put(FilterConstants.ISALPHABET_TAG, parameter_value.IsCharacter );
    		ParameterData.put(FilterConstants.ISFILE_TAG, parameter_value.IsFile );
        	ParameterInfo.put(parameter_name,ParameterData );
        	
        	//Add parameter to the parameter array
        	ParameterArray.add(ParameterInfo);
    	}
    	
	}
	/*****************************************************************************
	Function Name:WriteOutputFile
	Function Parameters:Output File Path
	Function Description:Function that writes the output file (i.e) input to next phase
	*****************************************************************************/
	public static void WriteOutputFile(String OUTPUTFILEPATH)
	{
		try
		{
        Iterator<Map.Entry <String, Payload>> refererurllist = DataManager.getInstance().refererurlmap.entrySet().iterator();
        /* Iterate the HashMap and print contents */
        System.out.println("Printing map contents to JSON File");   
        //JSONObject jsonParameterData = new JSONObject(DataManager.getInstance().refererurlmap);
        JSONArray jsonArrayOfRequest = new JSONArray();
        while (refererurllist.hasNext()) {
        	
        	Map.Entry <String, Payload> entry = refererurllist.next();
        	
        	//Get the URL and the payload associated with the URL
        	String refererurl = entry.getKey();
        	Payload temp = (Payload)entry.getValue();
        	
        	System.out.println("URL::" + refererurl);
        	
        	//Write Header Information
        	JSONObject ObjHeaderInfo = new JSONObject();
        	WriteHeader(ObjHeaderInfo,temp.header_data);
        		        	
  	        //Write Parameter Information        	
        	JSONArray ParameterArray = new JSONArray();
        	WriteParameter(ParameterArray,temp.variables_data);

        	//Write the Payload Information
        	JSONObject PayloadInfo = new JSONObject();
        	PayloadInfo.put(FilterConstants.HEADER, ObjHeaderInfo);
        	PayloadInfo.put(FilterConstants.PARAMETERS, ParameterArray);
        	
        	JSONObject jsonParameterData = new JSONObject();
        	jsonParameterData.put(refererurl, PayloadInfo);
        	
        	//Add the parameter in the Arraylist of requests
        	jsonArrayOfRequest.add(jsonParameterData)  ;    	       	
            //System.out.println("Key = " + entry.getKey() + ", Value = " + temp.genericinfo.content_length_average);
        	
        }//After all the requests have been iterated
        
        JSONObject outputrequests = new JSONObject();
        outputrequests.put(FilterConstants.REQUESTS,jsonArrayOfRequest );
        outputrequests.put(FilterConstants.MAX_PARAMETERS,DataManager.getInstance().maximum_number_of_parameters);
        	        
        /* File writing Logic */
        FileWriter file = new FileWriter(OUTPUTFILEPATH,false);
        file.write(outputrequests.toJSONString());  
        System.out.println("Successfully Copied JSON Object to File...");
        //System.out.println("\nJSON Object: " + jsonParameterData);
        file.flush();
        file.close();
        
        //Flag that indicates the learning phase completion
        WAFParameters.getInstance().SetLearning(false);
        
	} catch (FileNotFoundException ex) {
		ex.printStackTrace();
	} catch (IOException ex) {
		ex.printStackTrace();
	} catch (NullPointerException ex) {
		ex.printStackTrace();
	}
	}

}
