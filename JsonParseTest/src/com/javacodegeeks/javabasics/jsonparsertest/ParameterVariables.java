package com.javacodegeeks.javabasics.jsonparsertest;

import java.util.ArrayList;

public class ParameterVariables {
	
	ArrayList<String> parameterValues;
	VariableValidation validationrules;
	
	ParameterVariables()
	{
		validationrules = new VariableValidation();
		parameterValues = new ArrayList<String>();
	}
	
}
