package pt.unl.fct.di.adc.firstwebapp.util;

public class DeleteAccountData{
	
    public String username;
    
    public DeleteAccountData(){}
    
    public DeleteAccountData(String userId) {
    	this.username = userId;
    }
	
    public boolean isValidDeleteAccount() {
        return username != null && !username.isBlank();
    }
}