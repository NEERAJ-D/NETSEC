package com.netsec.firewall;

public class VariableValidation {
	public int max;
	public int average;
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
		standard_deviation = 0;
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
