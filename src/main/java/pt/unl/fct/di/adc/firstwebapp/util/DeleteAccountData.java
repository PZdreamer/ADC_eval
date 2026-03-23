package pt.unl.fct.di.adc.firstwebapp.util;

public class DeleteAccountData{
	
    public String userId;
    
    public DeleteAccountData(){}
    
    public DeleteAccountData(String username) {
    	this.userId = username;
    }
	
    public boolean isValidDeleteAccount() {
        return userId != null && !userId.isBlank();
    }
}