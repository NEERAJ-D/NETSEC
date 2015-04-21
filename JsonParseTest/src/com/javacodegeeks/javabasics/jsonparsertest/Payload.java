package com.javacodegeeks.javabasics.jsonparsertest;

import java.util.ArrayList;
import java.util.HashMap;
import com.javacodegeeks.javabasics.jsonparsertest.ParameterVariables;
import com.javacodegeeks.javabasics.jsonparsertest.HeaderInfo;
import com.javacodegeeks.javabasics.jsonparsertest.VariableValidation;
public class Payload {

	//Object that stores the Header Information
	public HeaderInfo header_data;
	
	//Map that stores the Parameter Variable Information
	public HashMap<String,ParameterVariables> variables_data = null; 
	
	//Default Constructor 
	Payload()
	{
		//Initialize the Map of Parameters
		variables_data = new HashMap<String ,ParameterVariables >();
		//Create a new Header data object
		header_data = new HeaderInfo();
	}
	
}
