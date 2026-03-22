package pt.unl.fct.di.adc.firstwebapp.util;

public class LoginData {
    public String username;
    public String password;

    public LoginData() {}

    public boolean isValidLogin() {
        return username != null && !username.isBlank()
            && password != null && !password.isBlank();
    }
}