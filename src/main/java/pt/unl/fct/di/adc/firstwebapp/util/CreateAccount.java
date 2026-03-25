package pt.unl.fct.di.adc.firstwebapp.util;

public class CreateAccount {

    public String username;
    public String password;
    public String confirmation;
    public String phone;
    public String address;
    public String role;

    public CreateAccount() {}

    public CreateAccount(String username, String password, String confirmation,
                         String phone, String address, String role) {
        this.username = username;
        this.password = password;
        this.confirmation = confirmation;
        this.phone = phone;
        this.address = address;
        this.role = role;
    }

    private boolean nonEmptyOrBlank(String value) {
        return value != null && !value.isBlank();
    }

    private boolean isRoleValid(String role) {
        return "USER".equals(role) || "BOFFICER".equals(role) || "ADMIN".equals(role);
    }

    private boolean isValidEmailFormat(String value) {
        return value != null && value.contains("@");
    }

    public boolean isValidAccount() {
        return nonEmptyOrBlank(username)
                && isValidEmailFormat(username)
                && nonEmptyOrBlank(password)
                && nonEmptyOrBlank(confirmation)
                && confirmation.equals(password)
                && nonEmptyOrBlank(phone)
                && nonEmptyOrBlank(address)
                && nonEmptyOrBlank(role)
                && isRoleValid(role);
    }
}