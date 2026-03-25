package pt.unl.fct.di.adc.firstwebapp.util;

public class ChangeUserRoleData {

    public String username;
    public String newRole;

    public ChangeUserRoleData() {}

    public ChangeUserRoleData(String username, String newRole) {
        this.username = username;
        this.newRole = newRole;
    }

    private boolean nonEmptyOrBlank(String value) {
        return value != null && !value.isBlank();
    }

    private boolean isRoleValid(String role) {
        return "USER".equals(role) || "BOFFICER".equals(role) || "ADMIN".equals(role);
    }

    public boolean isValidChangeUserRole() {
        return nonEmptyOrBlank(username) && nonEmptyOrBlank(newRole) && isRoleValid(newRole);
    }
}