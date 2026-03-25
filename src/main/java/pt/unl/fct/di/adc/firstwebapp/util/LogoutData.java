package pt.unl.fct.di.adc.firstwebapp.util;

public class LogoutData {

    public String username;

    public LogoutData() {}

    public LogoutData(String username) {
        this.username = username;
    }

    private boolean nonEmptyOrBlank(String value) {
        return value != null && !value.isBlank();
    }

    public boolean isValidLogout() {
        return nonEmptyOrBlank(username);
    }
}