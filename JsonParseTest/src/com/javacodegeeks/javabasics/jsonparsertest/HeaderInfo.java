package com.javacodegeeks.javabasics.jsonparsertest;
import com.javacodegeeks.javabasics.jsonparsertest.VariableValidation;

import java.util.ArrayList;

public class HeaderInfo {
	
		/* Class Contains generic information that needs to be stored */
		
		VariableValidation validation_variable;
	
		public int total_number_of_variables;
		public String user_agent;
		public String method;
		public int totalrequests;
		
		//Default Constructor
		HeaderInfo ()
		{
			validation_variable = new VariableValidation();
			total_number_of_variables  = 0;
			user_agent = "";
			method = "";
		}
		
		//Parameterized Constructor
		HeaderInfo(int contentlengthmax,int contentlengthaverage,int contentlengthmin,int totalnumberofvariables,String ua,String accessmethod){
			
			total_number_of_variables = totalnumberofvariables;
			user_agent = ua;	
			method = accessmethod;
		}
		
		
}
