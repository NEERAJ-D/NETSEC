package com.javacodegeeks.javabasics.jsonparsertest;

public class VariableValidation {
	public int max;
	public int average;
	public int min;
	String dataType;
	public VariableValidation() {
		// TODO Auto-generated constructor stub
		max = 0;
		average = 0;
		min = Integer.MAX_VALUE;
		dataType = "";
	}
	public VariableValidation(int nmax,int naverage,int nmin,String dttype) {
		// TODO Auto-generated constructor stub
		max = nmax;
		average = naverage;
		min = nmin;
		dataType = dttype;
	}
	
}
