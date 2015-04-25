package com.netsec.firewall;

import java.util.*;
import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FilterRequests {
	
	public static String[] properties= new String[100];
	
	public static void learnsignatures(){
		
		try {
			int i=0;
			File file = new File("properties.txt");
			FileReader fileReader = new FileReader(file);
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			String line;
			while ((line = bufferedReader.readLine()) != null) {
				properties[i] = line;
			}
			fileReader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
		
	private static final Logger logger = Logger.getLogger("FilteredRequests");
	
	public static boolean filterRequests(UserRequest request) {
		
		request.getHeader().put("content-type","application/x-www-form-urlencoded");
		request.getHeader().put("connection","keep-alive");
		request.getHeader().put("host","localhost:8080");
		request.getHeader().put("accept-language","en-US,en;q\u003d0.8");
		request.getHeader().put("accept","text/html,application/xhtml+xml,application/xml;q\u003d0.9,image/webp,*/*;q\u003d0.8");
		request.getHeader().put("origin","http://localhost:8080");
		request.getHeader().put("user-agent","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.90 Safari/537.36");
		request.getHeader().put("cache-control","max-age\u003d0");
		request.getHeader().put("remoteAddress","127.0.0.1");
		request.getHeader().put("content-length","35");
		request.getHeader().put("method","POST");
		request.getHeader().put("referer","http://localhost:8080/TomcatValve/1");
		request.getHeader().put("accept-encoding","gzip, deflate");
		
	    request.getParameters().put("colour","dzcas");
	    request.getParameters().put("pic","SSRN-id2210935.pdf");
	    
		boolean sign = signaturefiltering(request.getHeader(),request.getParameters());
		if(!sign)
			return false;
		else
		{
			boolean profile = profilefiltering(request.getHeader(),request.getParameters());
			if(!profile)
				return false;
		}
		return true;
	}

	private static boolean signaturefiltering(Map<String, String> header,Map<String, String> parameters) {

		for(int i=0;i<properties.length;i++)
		{
			String[] str = properties[i].split(",");
		 
			if(str[0].equals(""))
			{
				boolean checkresult = checksigunature(header,parameters,str);
				if(checkresult == false)
					return false;
			}
			else
			{
				if(header.get("METHOD").equals(str[0]))
				{
					boolean checkresult = checksigunature(header,parameters,str);
					if(checkresult == false)
						return false;
				}
			}
		}	
		return true;
	}

	public static boolean checksigunature(Map<String, String> header,Map<String, String> parameters,String[] str){
		
		if(str[1].equals("HEADER"))
		{
			if(str[2].equals("*"))
			{
				//iterate all of header and check str[3]
				for (Map.Entry<String ,String> entry : header.entrySet()) {
					String value = entry.getValue();
					if(value.contains(str[3]))
						return false;
				}
			}
			else
			{
				if(header.get(str[2]) != null)
				{
					if(header.get(str[2]).contains(str[3]))
						return false;
				}
			}
		}
		else
		{
			if(str[2].equals("*"))
			{
				//iterate all of parameter and check str[3]
				for (Map.Entry<String ,String> entry : parameters.entrySet()) {
					String value = entry.getValue();
					if(value.contains(str[3]))
						return false;
				}
			}
			else
			{
				if(parameters.get(str[2]) != null)
				{
					if(parameters.get(str[2]).contains(str[3]))
						return false;
				}
			}
		}
		return true;
	}
	
	private static boolean profilefiltering(Map<String, String> header,Map<String, String> parameters) {
		boolean head = filterHeader(header);
		if(head == false)
			return false;
		else{
			boolean param = filterParameters(parameters);
			if(param == false)
				return false;
		}
		return true;
	}

	public static boolean filterHeader(Map<String, String> header) {
		
		String url = header.get("referer");
		Payload p = DataManager.getInstance().refererurlmap.get(url);
		
		int content_length = Integer.parseInt(header.get("content-length"));
		
		if(content_length > p.header_data.validation_variable.max)
		{
			logger.log(Level.SEVERE, "Header Content Length exceeded the limit");
			return false;
		}
		if(content_length < p.header_data.validation_variable.min)
		{
			logger.log(Level.SEVERE, "Header Content Length under the limit");
			return false;
		}
		
		return true;	
	}

	public static boolean filterParameters(Map<String, String> parameters) {
		
		int number;
		boolean temp = false;
		String url = parameters.get("referer");
		Payload p = DataManager.getInstance().refererurlmap.get(url);
		
		if(parameters.size() != p.variables_data.size()){
			logger.log(Level.SEVERE, "Incorrect number of Parameters");
			return false;
		}	
			
		for (Map.Entry<String ,ParameterVariables> entry : p.variables_data.entrySet()) {

			String key = entry.getKey();
			ParameterVariables value = entry.getValue();
			
			if(!parameters.containsKey(key)){
				logger.log(Level.SEVERE, "Invalid Parameter");
				return false;
			}
			String req_value = parameters.get(key);
			
			temp = DataManager.getInstance().IsFieldNumeric(req_value);
			
			if(temp)
			{
				number = Integer.parseInt(req_value);
				if(number > value.validationrules.max){
					logger.log(Level.SEVERE, "Value for "+key+" exceeded the limit");
					return false;
				}
				if(number < value.validationrules.min){
					logger.log(Level.SEVERE, "Value for "+key+" under the limit");
					return false;
				}
			}
			else
			{
				number = req_value.length();
				if(number > value.validationrules.max){
					logger.log(Level.SEVERE, "Content length for "+key+" exceeded the limit");
					return false;
				}
				if(number < value.validationrules.min){
					logger.log(Level.SEVERE, "Content length for "+key+" under the limit");
					return false;
				}
			}
			
			if(temp != value.IsNumeric){
				logger.log(Level.SEVERE, "Type mismatch : Numeric value expected");
				return false;
			}
			
			temp = DataManager.getInstance().IsFieldEmailID(req_value);
			if(temp != value.IsEmailID){
				logger.log(Level.SEVERE, "Not an valid Email");
				return false;
			}
			
			temp = DataManager.getInstance().IsFieldAlphaNumeric(req_value);
			if(temp != value.IsAlphaNumeric){
				logger.log(Level.SEVERE, "Type mismatch : Alpha Numeric value expected");
				return false;
			}
			
			temp = DataManager.getInstance().IsFieldAlphabet(req_value);
			if(temp != value.IsCharacter){
				logger.log(Level.SEVERE, "Type mismatch : only Alphabets expected");
				return false;
			}
		}
		return true;
	}

}
