package pt.unl.fct.di.adc.firstwebapp.util;

public class LoginData {

    public String username;
    public String password;

    public LoginData() {}

    public LoginData(String username, String password) {
        this.username = username;
        this.password = password;
    }

    private boolean nonEmptyOrBlank(String value) {
        return value != null && !value.isBlank();
    }

    private boolean isValidEmailFormat(String value) {
        return value != null && value.contains("@");
    }

    public boolean isValidLogin() {
        return nonEmptyOrBlank(username)
                && isValidEmailFormat(username)
                && nonEmptyOrBlank(password);
    }
}