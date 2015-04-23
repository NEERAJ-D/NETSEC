package com.netsec.firewall;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.netsec.firewall.*;
public class JsonParseTest {

	private static final String INPUTFILEPATH = "D:\\Study\\Network Security\\logfile.json";
	private static final String OUTPUTFILEPATH = "D:\\Study\\Network Security\\logfile.json";
		
	public static void main(String[] args) {
		
		//Input File Path is received either from a properties file or from Valve during request for learning
		
		
		//Trigger Learning
		StartLearning(INPUTFILEPATH,OUTPUTFILEPATH);

	}
	public static void StartLearning(String inputfile,String outputfile)
	{
		try {
			
			//Provides the input log file for learning
			FileManager.InitializeLearningInput(inputfile);
			
			//Returns a JSONArray of requests
			JSONArray requests = FileManager.ReadLearningInput();
					
			//Parses all requests and stores in internal data structures
			FileManager.ParseAllRequests(requests);
	        
			//Writes an output file at specified path for filtering phase to read
			FileManager.WriteOutputFile(outputfile);
	        	
		} catch (NullPointerException ex) {
			ex.printStackTrace();
		}
	}

}
