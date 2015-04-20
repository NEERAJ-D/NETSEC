package com.javacodegeeks.javabasics.jsonparsertest;

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
		validationrules = new VariableValidation();
		parameterValues = new ArrayList<String>();
	}
	
}
