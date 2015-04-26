package com.netsec.firewall;

import java.io.IOException;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.json.simple.parser.ParseException;
/*****************************************************************************
Class Name:JsonParseTest
Class Description:Wrapper Class responsible for invoking all functionality
*****************************************************************************/
public class JsonParseTest {

	//TODO Accept these strings from a constants file 
	//temporary declarations
	private static final String INPUTFILEPATH = WAFParameters.getLOG_FILE();
	private static final String OUTPUTFILEPATH = WAFParameters.getMODEL_FILE();
	
	private static final Logger logger = Logger.getLogger("NETSEC");
	
	/*****************************************************************************
	Function Name:StartLearning
	Function Parameters:
	Function Description:Function that triggers the Learning Phase
	*****************************************************************************/

	public static void StartLearning()
	{
		try {
			
			//Read the Input File String from properties file constant
			String inputfile = INPUTFILEPATH;
			//Read the Output file String constant from properties file constant
			String outputfile = OUTPUTFILEPATH;
			
			
			
			logger.debug("Starting learning process...");
			
			//Provides the input log file for learning
			FileManager.InitializeLearningInput(inputfile);
			
			//Returns a JSONArray of requests
			FileManager.ReadLearningInput();
					
			//Parses all requests and stores in internal data structures
			FileManager.ParseAllRequests();
	        
			//Writes an output file at specified path for filtering phase to read
			FileManager.WriteOutputFile(outputfile);
			
				        	
		} catch (NullPointerException ex) {
			ex.printStackTrace();
		} catch (IOException ex) {
		
			ex.printStackTrace();
		} catch (ParseException ex) {
		
			ex.printStackTrace();
		}
	}

}
