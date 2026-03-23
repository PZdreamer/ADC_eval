package pt.unl.fct.di.adc.firstwebapp.util;

public class AccountAttributes {

    public String email;
    public String username;
    public String phone;
    public String address;

    public AccountAttributes() {}

    public boolean isValidAttributes() {
        boolean hasAtLeastOneAttribute =
                (email != null && !email.isBlank()) || (phone != null && !phone.isBlank())
                || (address != null && !address.isBlank()) || (username != null && !username.isBlank());

        boolean validEmail = (email == null || email.isBlank() || email.contains("@"));

        return hasAtLeastOneAttribute && validEmail;
    }
}