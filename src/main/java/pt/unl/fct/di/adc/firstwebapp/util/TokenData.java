package pt.unl.fct.di.adc.firstwebapp.util;

import com.google.cloud.datastore.Entity;

public class TokenData {

	public String tokenId;
	public String userId;
	public String role;
	public long issuedAt;
	public long expiresAt;

	public TokenData() {
	}

	public TokenData(String tokenId, String userId, String role, long issuedAt, long expiresAt) {
		this.tokenId = tokenId;
		this.userId = userId;
		this.role = role;
		this.issuedAt = issuedAt;
		this.expiresAt = expiresAt;
	}

	private boolean nonEmptyOrBlank(String value) {
		return value != null && !value.isBlank();
	}

	private boolean isRoleValid(String role) {
		return "USER".equals(role) || "BOFFICER".equals(role) || "ADMIN".equals(role);
	}

	public boolean isValidTokenFormat() {
		return nonEmptyOrBlank(tokenId) && nonEmptyOrBlank(userId) && nonEmptyOrBlank(role) && isRoleValid(role)
				&& issuedAt > 0 && expiresAt > 0 && expiresAt > issuedAt;
	}

	public boolean matchesStoredToken(TokenData storedToken) {
		return storedToken != null
				&& tokenId.equals(storedToken.tokenId)
				&& userId.equals(storedToken.userId)
				&& role.equals(storedToken.role)
				&& issuedAt == storedToken.issuedAt
				&& expiresAt == storedToken.expiresAt;
	}
	public static TokenData fromEntity(Entity tokenEntity) {
		return new TokenData(tokenEntity.getKey().getName(), tokenEntity.getString("token_username"),
				tokenEntity.getString("token_role"), tokenEntity.getLong("token_creationData"),
				tokenEntity.getLong("token_expirationData"));
	}
}