package com.javacodegeeks.javabasics.jsonparsertest;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class JsonParseTest {

	private static final String filePath = "D:\\Study\\Network Security\\logfile.json";
	
	public static void main(String[] args) {
		
		try {
			// read the json file
			FileReader reader = new FileReader(filePath);
			JSONParser jsonParser = new JSONParser();
			JSONObject jsonObject = (JSONObject) jsonParser.parse(reader);
			
			HashMap<String, Payload> refererurlmap = new HashMap<String, Payload>();
						
			JSONObject output = new JSONObject();

			JSONArray requests = (JSONArray) jsonObject.get("requests");
			
			Iterator singlerequest = requests.iterator();
			
			JSONObject parameter_contents=new JSONObject();
			
	        while (singlerequest.hasNext()) {
	        	//Single Request object
	            JSONObject request = (JSONObject) singlerequest.next();
	            
	            //Header of request
	            JSONObject header = (JSONObject) request.get("header");			
	            
	            //Parameter section of request
	            JSONObject parameters = (JSONObject) request.get("parameters");
	            	                     				
				// Extract method type
				String method =  (String) header.get("method");
				System.out.println("Method:: " + method);
				
				//Extract user-agent
				String user_agent =  (String) header.get("user-agent");
				System.out.println("User Agent:: " + user_agent);
				
				//Extract content-length
				String content_length =  (String) header.get("content-length");
				System.out.println("Content length:: " + content_length);
				
				//Extract referer
				String referer =  (String) header.get("referer");
				System.out.println("Referer:: " + referer);
				
				//If valid contents do exist on the page (Added Check since some pages do not have content-length
				if(content_length != null)
				{

				Integer ContentLength = Integer.parseInt(content_length);
		
				Payload temporary;
				if(refererurlmap.get(referer)!=null)
				{
					//Fetch the ParameterData for corresponding page
					temporary = refererurlmap.get(referer);
					
					//Check Maximum
					if(temporary.genericinfo.validation_variable.max < ContentLength)
						temporary.genericinfo.validation_variable.max = ContentLength;
						
					//Check Minimum
					if(temporary.genericinfo.validation_variable.min > ContentLength)
						temporary.genericinfo.validation_variable.min = ContentLength;
					
					//Update the average
					temporary.genericinfo.validation_variable.average = (temporary.genericinfo.validation_variable.average * temporary.genericinfo.totalrequests + ContentLength)/(temporary.genericinfo.totalrequests + 1);
				}
				else
				{
					//Object that holds generic info regarding a page
					temporary = new Payload();
				
					//temporary = ContentLength;
					temporary.genericinfo.validation_variable.min = ContentLength;
					temporary.genericinfo.validation_variable.max = ContentLength;
					temporary.genericinfo.validation_variable.average = ContentLength;
					
				}
				
				//Increment count of total requests
				temporary.genericinfo.totalrequests++;
				
				temporary.genericinfo.total_number_of_variables = parameters.size();
				
				//Possible Check can be added that checks if the content length size matches the actual parameters size
				//Act as a checksum
				
				//--------------------------
				
				//Start Processing for Parameters
				System.out.println("Number of Parameters::" + parameters.size());
					
				
				//Read page variables and their values
				
				
				//Read the variable names
				for ( Object key : parameters.keySet() ) { 
					 //System.out.println( key.toString() );
					 
					 System.out.println(key.toString() +":" + parameters.get(key.toString()));
					 String variable_name = (String)key.toString();
					 String variable_value = (String)parameters.get(variable_name);
					 					 
					 //Email ID regex
					 String regex_emailid = "(?:(?:\\r\\n)?[ \\t])*(?:(?:(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*|(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)*\\<(?:(?:\\r\\n)?[ \\t])*(?:@(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*(?:,@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*)*:(?:(?:\\r\\n)?[ \\t])*)?(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*\\>(?:(?:\\r\\n)?[ \\t])*)|(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)*:(?:(?:\\r\\n)?[ \\t])*(?:(?:(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*|(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)*\\<(?:(?:\\r\\n)?[ \\t])*(?:@(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*(?:,@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*)*:(?:(?:\\r\\n)?[ \\t])*)?(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*\\>(?:(?:\\r\\n)?[ \\t])*)(?:,\\s*(?:(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*|(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)*\\<(?:(?:\\r\\n)?[ \\t])*(?:@(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*(?:,@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*)*:(?:(?:\\r\\n)?[ \\t])*)?(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*\\>(?:(?:\\r\\n)?[ \\t])*))*)?;\\s*)";
					 Pattern pattern_emailid = Pattern.compile(regex_emailid);
					 //Check if E-mail field
					 boolean IsEmailid ;//= need to extract IsScriptPresent variable from stored;
					 IsEmailid =  (pattern_emailid.matcher(variable_value).matches() ? true : false);
					 	
					 //Check if the field is numeric
					 String regex_digit = "\\d+";
					 Pattern pattern_digit = Pattern.compile(regex_digit);
					 //Check if regex digit field
					 boolean IsNumeric  ;//= need to extract IsNumeric variable from stored;
					 IsNumeric =  (pattern_digit.matcher(variable_value).matches() ? true : false);
					 
					//Check if the field is alphanumeric 
					 String regex_alphanumeric = "\\[a-zA-Z0-9]+";
					 Pattern pattern_alphanumeric = Pattern.compile(regex_alphanumeric);
					 //Check if regex digit field
					 boolean IsAlphanumeric  ;//= need to extract IsAlphanumeric variable from stored;
					 IsAlphanumeric =  (pattern_alphanumeric.matcher(variable_value).matches() ? true : false);
					 
					 
					//Check if the field is alphabet
					 String regex_alphabet = "\\[a-zA-Z]+";
					 Pattern pattern_alphabet = Pattern.compile(regex_alphabet);
					 //Check if regex digit field
					 boolean IsAlphabet  ;//= need to extract IsAlphanumeric variable from stored;
					 IsAlphabet =  (pattern_alphabet.matcher(variable_value).matches() ? true : false);
					 
					 //Parameter variable temporary instance
					 ParameterVariables temp_instance;
					 if(temporary.variables_data.get(variable_name) != null)
					 {
						 temp_instance = temporary.variables_data.get(variable_name);
					 }
					 else
					 {
						 temp_instance = new ParameterVariables();
					 }
					 
					 //List of Valid values (can act as a white list)
					 temp_instance.parameterValues.add(variable_value);
					 
					 //Check maximum , minimum ,average
					//Check Maximum
					if(temp_instance.validationrules.max < ContentLength)
						temp_instance.validationrules.max = ContentLength;
						
					//Check Minimum
					if(temp_instance.validationrules.min > ContentLength)
						temp_instance.validationrules.min = ContentLength;
					
					//Update the average
					temp_instance.validationrules.average = (temp_instance.validationrules.average * temporary.genericinfo.totalrequests + ContentLength)/(temporary.genericinfo.totalrequests + 1);
					 
					//Below statements ensure that variable flags indicate the type of regex they satisfy
					//Any variable if violates the regex even a single time, then would not be checked further
					//In case an average case or standard deviation needs to be considered then all possible values need to be stored.
					
					if(temp_instance.IsAlphaNumeric)
					{
						temp_instance.IsAlphaNumeric = IsAlphanumeric;
					}
					if(temp_instance.IsNumeric)
					{
						temp_instance.IsNumeric = IsNumeric;
					}
					if(temp_instance.IsEmailID)
					{
						temp_instance.IsEmailID = IsEmailid;
					}
					if(temp_instance.IsCharacter)
					{
						temp_instance.IsCharacter = IsAlphabet;
					}
					
				
				//Update the record back in the Map
				refererurlmap.put(referer, temporary);
				
				} //Only perform all activities in the Loop if the content length is non-zero
				
				}
			
		
				System.out.println("-------------------");
				
	        }
	        
	        Iterator<Map.Entry <String, Payload>> refererurllist = refererurlmap.entrySet().iterator();
	        /* Iterate the HashMap and print contents */
	        System.out.println("Printing map contents to JSON File");   
	        JSONObject jsonParameterData = new JSONObject(refererurlmap);
	        JSONArray jsonArrayOfRequest = new JSONArray();
	        while (refererurllist.hasNext()) {
	        	Map.Entry <String, Payload> entry = refererurllist.next();
	        	String refererurl = entry.getKey();
	        	Payload temp = (Payload)entry.getValue();
	        	JSONObject HeaderInfo = new JSONObject();
	        	
	        	//JSONObject validheader = new JSONObject();
	        	HeaderInfo.put("max", temp.genericinfo.validation_variable.max);
	        	HeaderInfo.put("min", temp.genericinfo.validation_variable.min);
	        	HeaderInfo.put("average", temp.genericinfo.validation_variable.average);
	        	//HeaderInfo.put("datatype", temp.genericinfo.validation_variable.dataType);
	        	HeaderInfo.put("totalparameters", temp.genericinfo.totalrequests);
	        		        	
	        	//HeaderInfo.put("header", validheader);
	        	        	
	        	
	        	//-----------------------------
	        	//Parameter Info needs to be written to the JSON File
	        	JSONObject ParameterInfo = new JSONObject();
	        	    	
	        	
	        	JSONObject PayloadInfo = new JSONObject();
	        	
	        	PayloadInfo.put("header", HeaderInfo);
	        	PayloadInfo.put("parameters", ParameterInfo);
	        	jsonParameterData.put(refererurl, PayloadInfo);
	        	jsonArrayOfRequest.add(jsonParameterData)  ;    	       	
	            //System.out.println("Key = " + entry.getKey() + ", Value = " + temp.genericinfo.content_length_average);
	        	
	        }//After all the requests have been iterated
	        
	        JSONObject outputrequests = new JSONObject();
	        outputrequests.put("requests",jsonArrayOfRequest );
	        	        
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
		} catch (ParseException ex) {
			ex.printStackTrace();
		} catch (NullPointerException ex) {
			ex.printStackTrace();
		}

	}

}
