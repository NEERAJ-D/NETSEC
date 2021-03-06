package com.netsec.firewall;
/*****************************************************************************
Class Name:VariableValidation
Class Description:Class responsible for validation of variables having min,max,average etc.
*****************************************************************************/
public class VariableValidation {
	public int max;
	public double average;
	public int min;
	public double standard_deviation;
	String dataType;
	public VariableValidation() {
		// TODO Auto-generated constructor stub
		max = 0;
		average = 0;
		min = Integer.MAX_VALUE;
		standard_deviation = 0.0;
		dataType = "";
		
	}
	public VariableValidation(int nmax,int naverage,int nmin,String dttype, double standard_dev) {
		// TODO Auto-generated constructor stub
		max = nmax;
		average = naverage;
		min = nmin;
		dataType = dttype;
		standard_deviation = standard_dev;
	}
	
}
