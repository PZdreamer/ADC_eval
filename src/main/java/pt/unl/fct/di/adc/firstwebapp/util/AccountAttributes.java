package pt.unl.fct.di.adc.firstwebapp.util;

public class AccountAttributes {

    public String phone;
    public String address;

    public AccountAttributes() {}

    private boolean nonEmptyOrBlank(String value) {
        return value != null && !value.isBlank();
    }

    public boolean isValidAttributes() {
        return nonEmptyOrBlank(phone) || nonEmptyOrBlank(address);
    }
}