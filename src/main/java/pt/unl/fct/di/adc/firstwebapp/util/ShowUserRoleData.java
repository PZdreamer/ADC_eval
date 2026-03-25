package pt.unl.fct.di.adc.firstwebapp.util;

public class ShowUserRoleData{
	
	public String username;
	
	public ShowUserRoleData() {}
	
	public ShowUserRoleData(String username) {
		this.username = username;
	}
	
	private boolean nonEmptyOrBlank(String value) {
		return value != null && !value.isBlank();
	}
	
	public boolean isValidEmailFormat(String value) {
		return value != null && value.contains("@");
	}
	
	public boolean isValid() {
		return nonEmptyOrBlank(username) && isValidEmailFormat(username);
	}
	}