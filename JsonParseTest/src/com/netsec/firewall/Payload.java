package com.netsec.firewall;

import java.util.ArrayList;
import java.util.HashMap;

import com.netsec.firewall.HeaderInfo;
import com.netsec.firewall.ParameterVariables;
import com.netsec.firewall.VariableValidation;
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
