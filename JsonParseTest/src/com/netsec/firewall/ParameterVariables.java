package com.netsec.firewall;

import java.util.ArrayList;

public class ParameterVariables {
	
	ArrayList<String> parameterValues;
	VariableValidation validationrules;
	
	//Boolean Variables that store the regular expression rules
	boolean IsEmailID;
	boolean IsNumeric;
	boolean IsAlphaNumeric;
	boolean IsCharacter;
	
	ParameterVariables()
	{
		IsEmailID = true;
		IsNumeric = true;
		IsAlphaNumeric = true;
		IsCharacter = true;
		validationrules = new VariableValidation();
		parameterValues = new ArrayList<String>();
	}
	
}
