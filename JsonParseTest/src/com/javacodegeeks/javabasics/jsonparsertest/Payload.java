package com.javacodegeeks.javabasics.jsonparsertest;

import java.util.ArrayList;
import java.util.HashMap;
import com.javacodegeeks.javabasics.jsonparsertest.ParameterVariables;
import com.javacodegeeks.javabasics.jsonparsertest.ParameterData;
import com.javacodegeeks.javabasics.jsonparsertest.VariableValidation;
public class Payload {

	public ParameterData genericinfo;
	public HashMap<String,ParameterVariables> variables_data = null; 
	
	Payload()
	{
		variables_data = new HashMap<String ,ParameterVariables >();
		genericinfo = new ParameterData();
	}
	Payload(ParameterData pdata)
	{
		genericinfo = pdata;
	}
}
