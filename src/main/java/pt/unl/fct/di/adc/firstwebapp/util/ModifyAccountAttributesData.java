package pt.unl.fct.di.adc.firstwebapp.util;

public class ModifyAccountAttributesData {

    public String userId;
    public AccountAttributes attributes;

    public ModifyAccountAttributesData() {}

    public boolean isValidModifyAccountAttributes() {
        return userId != null && !userId.isBlank() && attributes != null && attributes.isValidAttributes();
    }
}