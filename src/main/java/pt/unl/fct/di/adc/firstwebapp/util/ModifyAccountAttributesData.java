package pt.unl.fct.di.adc.firstwebapp.util;

public class ModifyAccountAttributesData {

    public String username;
    public AccountAttributes attributes;

    public ModifyAccountAttributesData() {}

    public ModifyAccountAttributesData(String username, AccountAttributes attributes) {
        this.username = username;
        this.attributes = attributes;
    }

    private boolean nonEmptyOrBlank(String value) {
        return value != null && !value.isBlank();
    }

    public boolean isValidModifyAccountAttributes() {
        return nonEmptyOrBlank(username) && attributes != null && attributes.isValidAttributes();
    }
}