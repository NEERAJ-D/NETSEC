package com.netsec.firewall;

import java.util.HashMap;
import java.util.regex.Pattern;

import org.json.simple.JSONObject;

/*****************************************************************************
Class Name:DataManager
Class Description:Singleton data store
*****************************************************************************/
public class DataManager {
	//boolean ispagevalid;
	
	/*
	public boolean IsPageValid()
	{
		return ispagevalid;
	}
	*/
	
	int maximum_number_of_parameters;
	
	//Singleton Design Pattern
	private static DataManager instance = null;
	   protected DataManager() {
	      // Exists only to defeat instantiation.
		   refererurlmap = new HashMap<String, Payload>();
		   maximum_number_of_parameters = 0;
		   current_header = new JSONObject();
		   current_parameters = new JSONObject();
	   }
	/*****************************************************************************
	Function Name:getInstance
	Function Parameters:None
	Function Description:Singleton implementation
	*****************************************************************************/
	   public static DataManager getInstance() {
	      if(instance == null) {
	         instance = new DataManager();
	      }
	      return instance;
	   }
		   
	  //Referer URL --> Payload Map
	   HashMap<String, Payload> refererurlmap;
	   
	   //Current Header and Current Parameter
	   JSONObject current_header;
	   JSONObject current_parameters;
	   
	   //Functions
	   
	   public void setmap(HashMap<String, Payload> rf)
	   {
		   refererurlmap = rf;
		   
	   }
	   public void setmaxparameters(int maxx)
	   {
		   maximum_number_of_parameters = maxx;
	   }
	   
	   /*****************************************************************************
		Function Name:ReadFromJSONObject
		Function Parameters:None
		Function Description:Read JSON Object for a particular key
		*****************************************************************************/
	   public String ReadFromJSONObject(JSONObject obj,String param)
	   {
		   return (String) obj.get(param);
	   }

	   /*****************************************************************************
		Function Name:ValidatePayload
		Function Parameters:None
		Function Description:Validate and populate the data structure for Payload
		*****************************************************************************/
	   public void ValidatePayload()
	   {
		   String method = null,user_agent = null,content_length = null,referer = null;
		   	// Extract method type
		   if(current_header!=null)
		   		method =  ReadFromJSONObject(current_header,FilterConstants.METHOD);
			
			//Extract user-agent
		   if(current_header!=null)
			   user_agent = ReadFromJSONObject(current_header,FilterConstants.USERAGENT); 
			
			//Extract content-length
		   if(current_header!=null)
			 content_length = ReadFromJSONObject(current_header,FilterConstants.CONTENTLENGTH); 
			
			//Extract referer
		   if(current_header!=null)
			 referer =  ReadFromJSONObject(current_header,FilterConstants.REFERER);
			
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
						
						//Store the method that page uses
						temporary.header_data.method = method;
						
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
					temporary.header_data.total_number_of_variables = current_parameters.size();
			
					//Validate the parameters
					if(current_parameters.size()!=0)
						ValidateParameters(current_parameters,temporary);
					
					//Update the record back in the Map
					refererurlmap.put(referer, temporary);
				}
		
	   }
	   /*****************************************************************************
		Function Name:IsFieldEmailID
		Function Parameters:variable_value
		Function Description:Check if the variable value is an email id
		*****************************************************************************/
	   public boolean IsFieldEmailID(String variable_value)
	   {
		   Pattern pattern_emailid = Pattern.compile(FilterConstants.regex_emailid);
		   //Check if E-mail field
			boolean IsEmailid =  (pattern_emailid.matcher(variable_value).matches() ? true : false);
			return IsEmailid;
	   }
	   /*****************************************************************************
		Function Name:IsFieldNumeric
		Function Parameters:variable_value
		Function Description:Check if the variable value is numeric
		*****************************************************************************/
	   public boolean IsFieldNumeric(String variable_value)
	   {
			 Pattern pattern_digit = Pattern.compile(FilterConstants.regex_digit);
			 //Check if regex digit field
			 boolean IsNumeric  ;//= need to extract IsNumeric variable from stored;
			 IsNumeric =  (pattern_digit.matcher(variable_value).matches() ? true : false);
			 return  IsNumeric;
	   }
	   /*****************************************************************************
		Function Name:IsFieldAlphaNumeric
		Function Parameters:variable_value
		Function Description:Check if the variable value is alpha numeric
		*****************************************************************************/
	   public boolean IsFieldAlphaNumeric(String variable_value)
	   {
		   Pattern pattern_alphanumeric = Pattern.compile(FilterConstants.regex_alphanumeric);
			 //Check if regex digit field
			 boolean IsAlphanumeric  ;//= need to extract IsAlphanumeric variable from stored;
			 IsAlphanumeric =  (pattern_alphanumeric.matcher(variable_value).matches() ? true : false);
			 return IsAlphanumeric;
	   }
	   /*****************************************************************************
		Function Name:IsFieldAlphabet
		Function Parameters:variable_value
		Function Description:Check if the variable value is character
		*****************************************************************************/
	   public boolean IsFieldAlphabet(String variable_value)
	   {
			 Pattern pattern_alphabet = Pattern.compile(FilterConstants.regex_alphabet);
			 //Check if regex digit field
			 boolean IsAlphabet  ;//= need to extract IsAlphanumeric variable from stored;
			 IsAlphabet =  (pattern_alphabet.matcher(variable_value).matches() ? true : false);
			 return IsAlphabet;
	   }
	   /*****************************************************************************
		Function Name:IsFieldFile
		Function Parameters:variable_value
		Function Description:Check if the variable value is a file
		*****************************************************************************/
	   public boolean IsFieldFile(String variable_value)
	   {
			 Pattern pattern_alphabet = Pattern.compile(FilterConstants.regex_file);
			 //Check if regex digit field
			 boolean IsFile  ;//= need to extract IsAlphanumeric variable from stored;
			 IsFile =  (pattern_alphabet.matcher(variable_value).matches() ? true : false);
			 return IsFile;
	   }
	   /*****************************************************************************
		Function Name:ValidateParameters
		Function Parameters:Payload Object
		Function Description:Validate the parameters and store the paramters
		*****************************************************************************/
	   private void ValidateParameters(JSONObject parameters,Payload temporary)
	   {
		   
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
				
				boolean IsFile = IsFieldFile(variable_value);
				 
				 //Parameter variable temporary instance
				 ParameterVariables temp_instance;
				 if(temporary.variables_data.get(variable_name) != null)
				 {
					 temp_instance = temporary.variables_data.get(variable_name);
				 }
				 else
				 {
					 temp_instance = new ParameterVariables();
					 if(IsEmailid)
						{
							temp_instance.IsEmailID = IsEmailid;
						}
						else
						{
							if(IsNumeric)
							{
								temp_instance.IsNumeric = IsNumeric;
							}
							else
							{
								if(IsFile)
								{
									temp_instance.IsFile = IsFile;
									//In case a File type Regex is matched then all the variables are reset to 0
									temp_instance.validationrules.average = 0;
									temp_instance.validationrules.max = 0;
									temp_instance.validationrules.min = 0;
									temp_instance.validationrules.standard_deviation = 0;
								}
								else
								{
									if(IsAlphabet)
									{
										temp_instance.IsCharacter = IsAlphabet;
									}
									else if(IsAlphanumeric)
									{
										temp_instance.IsAlphaNumeric = IsAlphanumeric;
									}
								}
							}
						}
					 
				}
				 
				 //List of Valid values (can act as a white list)
				 //temp_instance.parameterValues.add(variable_value);
				 
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
				
				//Add the content length to the list for calculation of standard deviation
				 temp_instance.listofcontentlengths.add(contentlength);
				 
				//Update the average
				temp_instance.validationrules.average = (temp_instance.validationrules.average * temp_instance.numberofinstances + contentlength)/(temp_instance.numberofinstances + 1);
				temp_instance.numberofinstances++;

				//Below statements ensure that variable flags indicate the type of regex they satisfy
				//Any variable if violates the regex even a single time, then would not be checked further
				//In case an average case or standard deviation needs to be considered then all possible values need to be stored.
				
				
				/*
				 * NEED NOT ITERATIVELY PERFORM THIS CHECK AS LEARNING ALWAYS INVOLVES CORRRECT INPUT
				 * UNCOMMENT IF LEARNING DECIDE TO TRAIN ON INCORRECT INPUT ALSO
				//temp_instance.IsAlphaNumeric has been initialized to true, so first time value is true, and if true only then 
				//check if next value is true, first time false appears do not check from next time

				*/
					
				//add variables to map (variable_name --> ParameterVariables structure )
				temporary.variables_data.put(variable_name, temp_instance);
			
			} //Only perform all activities in the Loop if the content length is non-zero
			
	   }
}
