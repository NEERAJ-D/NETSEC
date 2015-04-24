package com.netsec.firewall;

import java.util.HashMap;

/*****************************************************************************
Class Name:Payload
Class Description:Stores the Header and Parameter for a single URL
*****************************************************************************/
public class Payload {

	//Object that stores the Header Information
	public HeaderInfo header_data;
	
	//Map that stores the Parameter Variable Information
	public HashMap<String,ParameterVariables> variables_data = null; 
	
	public Integer maximum_number_of_parameters;
	
	//Default Constructor 
	Payload()
	{
		//Initialize the Map of Parameters
		variables_data = new HashMap<String ,ParameterVariables >();
		//Create a new Header data object
		header_data = new HeaderInfo();
	}
	
}
