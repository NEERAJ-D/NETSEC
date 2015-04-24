package com.netsec.firewall;

import java.io.IOException;

import org.json.simple.parser.ParseException;
public class JsonParseTest {

	private static final String INPUTFILEPATH = "D:\\Study\\Network Security\\training.log";
	
	private static final String OUTPUTFILEPATH = "D:\\Study\\Network Security\\modelfile.json";
	
	private static final String IntermediaryFile = "D:\\Study\\Network Security\\requests.log";
	
	public static void main(String[] args) throws IOException {
		
		//Input File Path is received either from a properties file or from Valve during request for learning
		
		
		/*
		FileReader fr = new FileReader(IntermediaryFile);
		BufferedReader br = new BufferedReader(fr);
		
	
		FileWriter fileWritter = new FileWriter(INPUTFILEPATH,true);
        BufferedWriter bufferWritter = new BufferedWriter(fileWritter);
        bufferWritter.write("{\"requests\":[");
        
        
        int c=br.read();
		while(c!=-1) {
			bufferWritter.write(c);
		    c = br.read();
		}
		
		bufferWritter.write("]}");
		bufferWritter.close();
		
		*/
		
		//Trigger Learning
		StartLearning(INPUTFILEPATH,OUTPUTFILEPATH);

	}
	public static void StartLearning(String inputfile,String outputfile)
	{
		try {
			
			//Provides the input log file for learning
			FileManager.InitializeLearningInput(inputfile);
			
			//Returns a JSONArray of requests
			FileManager.ReadLearningInput();
					
			//Parses all requests and stores in internal data structures
			FileManager.ParseAllRequests();
	        
			//Writes an output file at specified path for filtering phase to read
			FileManager.WriteOutputFile(outputfile);
			
			//Clear the map after usage
			DataManager.getInstance().refererurlmap.clear();
				        	
		} catch (NullPointerException ex) {
			ex.printStackTrace();
		} catch (IOException ex) {
			// TODO Auto-generated catch block
			ex.printStackTrace();
		} catch (ParseException ex) {
			// TODO Auto-generated catch block
			ex.printStackTrace();
		}
	}

}
