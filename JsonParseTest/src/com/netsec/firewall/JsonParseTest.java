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

	private static final String FILEPATH = "D:\\Study\\Network Security\\logfile.json";
		
	public static void main(String[] args) {
		
		try {
			
			FileManager.InitializeLearningInput(FILEPATH);
			
			JSONArray requests = FileManager.ReadLearningInput();
					
			FileManager.ParseAllRequests(requests);
	            
			FileManager.WriteOutputFile();
	        	
		} catch (NullPointerException ex) {
			ex.printStackTrace();
		}
	        


	}

}
