package pt.unl.fct.di.adc.firstwebapp.util;

import java.util.UUID;

import com.google.cloud.datastore.Entity;

public class TokenData {

    public static final long EXPIRATION_TIME = 1000 * 60 * 15; 

    public String tokenId;
    public String username;
    public String role;
    public long issuedAt;
    public long expiresAt;

    public TokenData() {}

    public TokenData(String tokenId, String username, String role, long issuedAt, long expiresAt) {
        this.tokenId = tokenId;
        this.username = username;
        this.role = role;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public static TokenData createNew(String username, String role) {
        long now = System.currentTimeMillis();
        return new TokenData(UUID.randomUUID().toString(), username, role, now, now + EXPIRATION_TIME);
    }

    private boolean nonEmptyOrBlank(String value) {
        return value != null && !value.isBlank();
    }

    private boolean isRoleValid(String role) {
        return "USER".equals(role) || "BOFFICER".equals(role) || "ADMIN".equals(role);
    }

    public boolean isValidTokenFormat() {
        return nonEmptyOrBlank(tokenId) && nonEmptyOrBlank(username) && nonEmptyOrBlank(role) 
        		&& isRoleValid(role) && issuedAt > 0 && expiresAt > 0 && expiresAt > issuedAt;
    }

    public boolean matchesStoredToken(TokenData storedToken) {
        return storedToken != null && tokenId.equals(storedToken.tokenId) && username.equals(storedToken.username) 
        		&& role.equals(storedToken.role) && issuedAt == storedToken.issuedAt && expiresAt == storedToken.expiresAt;
    }

    public static TokenData fromEntity(Entity tokenEntity) {
        return new TokenData(tokenEntity.getKey().getName(), tokenEntity.getString("token_username"), 
        		tokenEntity.getString("token_role"), tokenEntity.getLong("token_creationData"), 
        		tokenEntity.getLong("token_expirationData"));
    }
}