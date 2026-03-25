package pt.unl.fct.di.adc.firstwebapp.util;

public class ChangeUserPasswordData {

    public String username;
    public String oldPassword;
    public String newPassword;

    public ChangeUserPasswordData() {}

    public ChangeUserPasswordData(String username, String oldPassword, String newPassword) {
        this.username = username;
        this.oldPassword = oldPassword;
        this.newPassword = newPassword;
    }

    private boolean nonEmptyOrBlank(String value) {
        return value != null && !value.isBlank();
    }

    public boolean isValidChangeUserPassword() {
        return nonEmptyOrBlank(username)
                && nonEmptyOrBlank(oldPassword)
                && nonEmptyOrBlank(newPassword);
    }
}