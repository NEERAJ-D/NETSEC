package com.javacodegeeks.javabasics.jsonparsertest;

import java.util.HashMap;
import java.util.regex.Pattern;

import org.json.simple.JSONObject;

import com.javacodegeeks.javabasics.jsonparsertest.*;
public class DataManager {

	
	//CONSTANT for regular expressions
	private static final String regex_emailid = "(?:(?:\\r\\n)?[ \\t])*(?:(?:(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*|(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)*\\<(?:(?:\\r\\n)?[ \\t])*(?:@(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*(?:,@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*)*:(?:(?:\\r\\n)?[ \\t])*)?(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*\\>(?:(?:\\r\\n)?[ \\t])*)|(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)*:(?:(?:\\r\\n)?[ \\t])*(?:(?:(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*|(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)*\\<(?:(?:\\r\\n)?[ \\t])*(?:@(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*(?:,@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*)*:(?:(?:\\r\\n)?[ \\t])*)?(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*\\>(?:(?:\\r\\n)?[ \\t])*)(?:,\\s*(?:(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*|(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)*\\<(?:(?:\\r\\n)?[ \\t])*(?:@(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*(?:,@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*)*:(?:(?:\\r\\n)?[ \\t])*)?(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*\\>(?:(?:\\r\\n)?[ \\t])*))*)?;\\s*)";
	private static final String regex_digit = "\\d+";
	private static final String regex_alphanumeric = "\\[a-zA-Z0-9]+";
	private static final String regex_alphabet = "\\[a-zA-Z]+";
	
	//Constants for File reading 
	private static final String REQUESTS = "requests";
	
	//Parameter Section
	private static final String PARAMETERS = "parameters";
	
	//Header Section
	private static final String HEADER = "header";
	private static final String USERAGENT = "user-agent";
	private static final String CONTENTLENGTH = "content-length";
	private static final String REFERER = "referer";
	private static final String METHOD = "method";
	
	boolean ispagevalid;
	
	
	public boolean IsPageValid()
	{
		return ispagevalid;
	}
	
	//Singleton Design Pattern
	private static DataManager instance = null;
	   protected DataManager() {
	      // Exists only to defeat instantiation.
		   refererurlmap = new HashMap<String, Payload>();
	   }
	   public static DataManager getInstance() {
	      if(instance == null) {
	         instance = new DataManager();
	      }
	      return instance;
	   }
	   
	   
	   
	  //Referer URL --> Payload Map
	   HashMap<String, Payload> refererurlmap;
	   
	   
	   
	   //Functions
	   
	   public String ReadFromJSONObject(JSONObject obj,String param)
	   {
		   return (String) obj.get(param);
	   }
	   
	   
   
	   //Validate the payload
	   //Input :: JSONObject Header , JSONObject Parameter
	   public void ValidatePayload(JSONObject header,JSONObject parameters)
	   {
		   	// Extract method type
		   	String method =  ReadFromJSONObject(header,METHOD);
			
			//Extract user-agent
			String user_agent = ReadFromJSONObject(header,USERAGENT); 
			
			//Extract content-length
			String content_length = ReadFromJSONObject(header,CONTENTLENGTH); 
			
			//Extract referer
			String referer =  ReadFromJSONObject(header,REFERER);
			
			//#DEBUG print statements
			System.out.println("Method:: " + method);
			System.out.println("User Agent:: " + user_agent);
			System.out.println("Content length:: " + content_length);
			System.out.println("Referer:: " + referer);
			Payload temporary;
			
			//If valid contents do exist on the page (Added Check since some pages do not have content-length
			if(content_length != null)
			{

				Integer contentlength = Integer.parseInt(content_length);
	
				//DataManager.getInstance().ValidatePayload(referer,contentlength,parameters);
			
			
					if(refererurlmap.get(referer)!=null)
					{
						//Fetch the ParameterData for corresponding page
						temporary = refererurlmap.get(referer);
						
						
						//Header Validation
						//Check Maximum
						if(temporary.header_data.validation_variable.max < contentlength)
							temporary.header_data.validation_variable.max = contentlength;
							
						//Check Minimum
						if(temporary.header_data.validation_variable.min > contentlength)
							temporary.header_data.validation_variable.min = contentlength;
						
						//Update the average
						temporary.header_data.validation_variable.average = (temporary.header_data.validation_variable.average * temporary.header_data.totalrequests + contentlength)/(temporary.header_data.totalrequests + 1);
					}
					else
					{
						//Object that holds generic info regarding a page
						temporary = new Payload();
					
						temporary.header_data.validation_variable.min = contentlength;
						temporary.header_data.validation_variable.max = contentlength;
						temporary.header_data.validation_variable.average = contentlength;
						
					}
					//Increment count of total requests
					temporary.header_data.totalrequests++;
			
					//Set the total number of variables in the current request
					temporary.header_data.total_number_of_variables = parameters.size();
			
					//Validate the parameters
					if(parameters.size()!=0)
						ValidateParameters(parameters,temporary);
					
					//Update the record back in the Map
					refererurlmap.put(referer, temporary);
				}
		
	   }
	   public boolean IsFieldEmailID(String variable_value)
	   {
		   Pattern pattern_emailid = Pattern.compile(regex_emailid);
		   //Check if E-mail field
			boolean IsEmailid =  (pattern_emailid.matcher(variable_value).matches() ? true : false);
			return IsEmailid;
	   }
	   public boolean IsFieldNumeric(String variable_value)
	   {
			 Pattern pattern_digit = Pattern.compile(regex_digit);
			 //Check if regex digit field
			 boolean IsNumeric  ;//= need to extract IsNumeric variable from stored;
			 IsNumeric =  (pattern_digit.matcher(variable_value).matches() ? true : false);
			 return  IsNumeric;
	   }
	   public boolean IsFieldAlphaNumeric(String variable_value)
	   {
		   Pattern pattern_alphanumeric = Pattern.compile(regex_alphanumeric);
			 //Check if regex digit field
			 boolean IsAlphanumeric  ;//= need to extract IsAlphanumeric variable from stored;
			 IsAlphanumeric =  (pattern_alphanumeric.matcher(variable_value).matches() ? true : false);
			 return IsAlphanumeric;
	   }
	   public boolean IsFieldAlphabet(String variable_value)
	   {
			 Pattern pattern_alphabet = Pattern.compile(regex_alphabet);
			 //Check if regex digit field
			 boolean IsAlphabet  ;//= need to extract IsAlphanumeric variable from stored;
			 IsAlphabet =  (pattern_alphabet.matcher(variable_value).matches() ? true : false);
			 return IsAlphabet;
	   }
	   private void ValidateParameters(JSONObject parameters,Payload temporary)
	   {
		   int variable_count = 0;
		 //Read the variable names
			for ( Object key : parameters.keySet() ) { 
				 //System.out.println( key.toString() );
				
				 System.out.println(key.toString() +":" + parameters.get(key.toString()));
				 String variable_name = (String)key.toString();
				 String variable_value = (String)parameters.get(variable_name);
				 					 
				 //Email ID regex
				 boolean IsEmailid = IsFieldEmailID(variable_value) ;
				 	
				 //Check if the field is numeric
				 boolean IsNumeric = IsFieldNumeric(variable_value);
				 
				//Check if the field is alphanumeric 
				 boolean IsAlphanumeric = IsFieldAlphaNumeric(variable_value);
				 
				//Check if the field is alphabet
				boolean IsAlphabet = IsFieldAlphabet(variable_value) ;
				 
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
				 
				 int contentlength = 0;
				 if(IsNumeric)
				 {
					 //Apply validation for min max based on value
					 contentlength = Integer.parseInt(variable_value);
					//Check Maximum
						if(temp_instance.validationrules.max < contentlength)
							temp_instance.validationrules.max = contentlength;
							
						//Check Minimum
						if(temp_instance.validationrules.min > contentlength)
							temp_instance.validationrules.min = contentlength;
				 }
				 else
				 {
					 //Apply validation based on text-length field
					 contentlength = variable_value.length();
					//Check Maximum
						if(temp_instance.validationrules.max < contentlength)
							temp_instance.validationrules.max = contentlength;
							
						//Check Minimum
						if(temp_instance.validationrules.min > contentlength)
							temp_instance.validationrules.min = contentlength;
				 }
				
				//Update the average
				temp_instance.validationrules.average = (temp_instance.validationrules.average * variable_count + contentlength)/(variable_count + 1);
				variable_count++;
				//Below statements ensure that variable flags indicate the type of regex they satisfy
				//Any variable if violates the regex even a single time, then would not be checked further
				//In case an average case or standard deviation needs to be considered then all possible values need to be stored.
				
				//temp_instance.IsAlphaNumeric has been initialized to true, so first time value is true, and if true only then 
				//check if next value is true, first time false appears do not check from next time
				if(temp_instance.IsEmailID)
				{
					temp_instance.IsEmailID = IsEmailid;
				}
				else
				{
					if(temp_instance.IsNumeric)
					{
						temp_instance.IsNumeric = IsNumeric;
					}
					else
					{
						if(temp_instance.IsCharacter)
						{
							temp_instance.IsCharacter = IsAlphabet;
						}
						else if(temp_instance.IsAlphaNumeric)
						{
							temp_instance.IsAlphaNumeric = IsAlphanumeric;
						}
						
					}
				}
				
		
				//File upload regular expressions to be written
			
				//add variables to map (variable_name --> ParameterVariables structure )
				temporary.variables_data.put(variable_name, temp_instance);
			
			} //Only perform all activities in the Loop if the content length is non-zero
			
	   }
}
