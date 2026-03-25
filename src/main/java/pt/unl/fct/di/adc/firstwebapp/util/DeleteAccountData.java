package pt.unl.fct.di.adc.firstwebapp.util;

public class DeleteAccountData{
	
    public String userId;
    
    public DeleteAccountData(){}
    
    public DeleteAccountData(String userId) {
    	this.userId = userId;
    }
	
    public boolean isValidDeleteAccount() {
        return userId != null && !userId.isBlank();
    }
}