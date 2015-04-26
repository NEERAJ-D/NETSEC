package com.netsec.firewall;

public interface FilterConstants {
	static final String CONTENT = "content";

	//CONSTANT for regular expressions

	//E-mail ID
	static final String regex_emailid = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";
	
	//Entire Number regular expressions
	static final String regex_entire_number = "\\d+";
	
	//Is Any single character digit
	static final String regex_digit = ".*\\d.*";
	
	//is any character a digit
	static final String regex_alphabet = ".*[a-zA-Z].*";
	
	//is the variable a file
	static final String regex_file = "\\Aimage/(.)*"; //Only Image Files are acceptable
	static final String regex_file_path = "((?:\\.\\.\\/)+)";
	static final String FILE_PATH = "filePath";
	
	//Constants for File reading 
	static final String REQUESTS = "requests";
	
	//Parameter Section
	static final String PARAMETERS = "parameters";
	
	//Header Section
	static final String HEADER = "header";
	static final String USERAGENT = "user-agent";
	static final String CONTENTLENGTH = "content-length";
	static final String REFERER = "referer";
	static final String METHOD = "method";
	static final String METHOD_GET = "GET";

	//Maximum parameters 
	static final String MAX_PARAMETERS = "maximum_number_of_parameters";
	
	//Output File Constants
	static final String MINIMUM_TAG  = "min";
	static final String MAXIMUM_TAG  = "max";
	static final String AVERAGE_TAG  = "average";
	static final String STANDARD_DEVIATION_TAG = "standard_deviation";
	
	//Header Section
	static final String TOTAL_PARAMETERS_TAG  ="totalparameters";
	static final String METHOD_TAG = "METHOD";
	static final String HEADER_TAG = "HEADER";
	
	//Parameter Section
	static final String ISEMAILID_TAG  ="is_email_id";
	static final String ISNUMERIC_TAG  ="is_numeric";
	static final String ISALPHABET_TAG  ="is_alphabet";
	static final String ISALPHANUMERIC_TAG  ="is_alphanumeric";
	static final String ISFILE_TAG = "is_file";
	
}
