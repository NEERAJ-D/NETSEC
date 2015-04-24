package com.netsec.firewall;

import java.util.ArrayList;

/*****************************************************************************
Class Name:ParameterVariables
Class Description:Class that stores all learned data for parameters
*****************************************************************************/

public class ParameterVariables {
	
	//Values can be stored for maintaining a list of values for whitelist
	ArrayList<String> parameterValues;
	
	//Used for calculation of Standard Deviation
	ArrayList<Integer> listofcontentlengths;
	
	//Validation of variables
	VariableValidation validationrules;
	
	int numberofinstances;
	
	//Boolean Variables that store the regular expression rules
	boolean IsEmailID;
	boolean IsNumeric;
	boolean IsAlphaNumeric;
	boolean IsCharacter;
	boolean IsFile;
	ParameterVariables()
	{
		
		validationrules = new VariableValidation();
		parameterValues = new ArrayList<String>();
		listofcontentlengths = new ArrayList<Integer>();
	}
	
}
