package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.ArrayList;
import java.util.List;

import com.google.cloud.datastore.Query;
import com.google.cloud.datastore.QueryResults;

import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreException;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.gson.Gson;

import pt.unl.fct.di.adc.firstwebapp.util.AuthenticatedRequest;
import pt.unl.fct.di.adc.firstwebapp.util.ChangeUserPasswordData;
import pt.unl.fct.di.adc.firstwebapp.util.ChangeUserRoleData;
import pt.unl.fct.di.adc.firstwebapp.util.CreateAccount;
import pt.unl.fct.di.adc.firstwebapp.util.Errors;
import pt.unl.fct.di.adc.firstwebapp.util.LoginData;
import pt.unl.fct.di.adc.firstwebapp.util.LogoutData;
import pt.unl.fct.di.adc.firstwebapp.util.ModifyAccountAttributesData;
import pt.unl.fct.di.adc.firstwebapp.util.DeleteAccountData;
import pt.unl.fct.di.adc.firstwebapp.util.EmptyInput;
import pt.unl.fct.di.adc.firstwebapp.util.OperationRequest;
import pt.unl.fct.di.adc.firstwebapp.util.ShowUserRoleData;
import pt.unl.fct.di.adc.firstwebapp.util.TokenData;

@Path("/")
public class AccountResource {

	private static final Logger LOG = Logger.getLogger(AccountResource.class.getName());

	private static final Datastore datastore = DatastoreOptions.newBuilder().setProjectId("adc-pei-2526").build().getService();

	private final Gson g = new Gson();

	public AccountResource() {
	}

	@POST
	@Path("/createaccount")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response createAccount(OperationRequest<CreateAccount> request) {
		if (request == null || request.input == null || !request.input.isValidAccount()) {
			return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_INPUT, Errors.MSG_INVALID_INPUT);
		}

		CreateAccount account = request.input;

		try {
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(account.username);

			Entity existingUser = datastore.get(userKey);

			if (existingUser != null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_ALREADY_EXISTS, Errors.MSG_USER_ALREADY_EXISTS);
			}

			Entity accountEntity = Entity.newBuilder(userKey).set("user_username", account.username)
					.set("user_pwd", DigestUtils.sha512Hex(account.password)).set("user_phone", account.phone)
					.set("user_address", account.address).set("user_role", account.role)
					.build();

			datastore.put(accountEntity);

			Map<String, Object> data = new LinkedHashMap<>();
			data.put("username", account.username);
			data.put("role", account.role);

			Map<String, Object> response = new LinkedHashMap<>();
			response.put("status", "success");
			response.put("data", data);

			return Response.ok(g.toJson(response)).build();

		} catch (DatastoreException e) {
			LOG.log(Level.SEVERE, e.toString(), e);

			return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}
	}

	@POST
	@Path("/login")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response login(OperationRequest<LoginData> request) {
		
		if (request == null || request.input == null || !request.input.isValidLogin()) {
			return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_NOT_FOUND, Errors.MSG_USER_NOT_FOUND);
		}

		LoginData login = request.input;

		try {
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(login.username);
			Entity userEntity = datastore.get(userKey);

			if (userEntity == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_NOT_FOUND, Errors.MSG_USER_NOT_FOUND);
			}

			String storedPasswordHash = userEntity.getString("user_pwd");
			String receivedPasswordHash = DigestUtils.sha512Hex(login.password);

			if (!storedPasswordHash.equals(receivedPasswordHash)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_CREDENTIALS, Errors.MSG_INVALID_CREDENTIALS);
			}

			String role = userEntity.getString("user_role");
	        TokenData token = TokenData.createNew(login.username, role);

			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(token.tokenId);

			Entity tokenEntity = Entity.newBuilder(tokenKey)
					.set("token_username", token.username)
					.set("token_creationData", token.issuedAt)
					.set("token_expirationData", token.expiresAt)
					.set("token_role", role)
					.build();

			datastore.put(tokenEntity);

			Map<String, Object> tokenData = new LinkedHashMap<>();
			tokenData.put("tokenId", token.tokenId);
			tokenData.put("username", token.username);
			tokenData.put("role", role);
			tokenData.put("issuedAt", token.issuedAt);
			tokenData.put("expiresAt", token.expiresAt);

			Map<String, Object> data = new LinkedHashMap<>();
			data.put("token", tokenData);

			Map<String, Object> response = new LinkedHashMap<>();
			response.put("status", "success");
			response.put("data", data);

			return Response.ok(g.toJson(response)).build();

		} catch (DatastoreException e) {
			LOG.log(Level.SEVERE, e.toString(), e);
			return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}
	}

	@POST
	@Path("/showusers")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response showUsers(AuthenticatedRequest<EmptyInput> request) {

		if (request == null || request.input == null) {
			return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_INPUT, Errors.MSG_INVALID_INPUT);
		}

		if (request.token == null || !request.token.isValidTokenFormat()) {
		    return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
		}
		
		try {
			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(request.token.tokenId);
			Entity tokenEntity = datastore.get(tokenKey);

			if (tokenEntity == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			TokenData storedToken = TokenData.fromEntity(tokenEntity);

			if (!request.token.matchesStoredToken(storedToken)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			if (System.currentTimeMillis() > storedToken.expiresAt) {
				datastore.delete(tokenKey);
				return errorResponse(Response.Status.BAD_REQUEST, Errors.TOKEN_EXPIRED, Errors.MSG_TOKEN_EXPIRED);
			}

			if (!"ADMIN".equals(storedToken.role) && !"BOFFICER".equals(storedToken.role)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
			}

			Query<Entity> query = Query.newEntityQueryBuilder().setKind("User").build();

			QueryResults<Entity> results = datastore.run(query);

			List<Map<String, Object>> users = new ArrayList<>();

			while (results.hasNext()) {
				Entity user = results.next();

				Map<String, Object> userData = new LinkedHashMap<>();
				userData.put("username", user.getString("user_username"));
				userData.put("role", user.getString("user_role"));

				users.add(userData);
			}

			Map<String, Object> data = new LinkedHashMap<>();
			data.put("users", users);

			Map<String, Object> response = new LinkedHashMap<>();
			response.put("status", "success");
			response.put("data", data);

			return Response.ok(g.toJson(response)).build();

		} catch (Exception e) {
			LOG.log(Level.SEVERE, e.toString(), e);
			return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}
	}

	@POST
	@Path("/deleteaccount")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response deleteAccount(AuthenticatedRequest<DeleteAccountData> request) {

		if (request == null || request.input == null || !request.input.isValidDeleteAccount()) {
			return errorResponse(Response.Status.BAD_REQUEST, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}

		if (request.token == null || !request.token.isValidTokenFormat()) {
		    return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
		}
		
		try {
			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(request.token.tokenId);
			Entity tokenEntity = datastore.get(tokenKey);

			
			if (tokenEntity == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			TokenData storedToken = TokenData.fromEntity(tokenEntity);

			if (!request.token.matchesStoredToken(storedToken)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			if (System.currentTimeMillis() > storedToken.expiresAt) {
				datastore.delete(tokenKey);
				return errorResponse(Response.Status.BAD_REQUEST, Errors.TOKEN_EXPIRED, Errors.MSG_TOKEN_EXPIRED);
			}

			if (!"ADMIN".equals(storedToken.role)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
			}

			Key userKey = datastore.newKeyFactory().setKind("User").newKey(request.input.username);
			Entity userEntity = datastore.get(userKey);

			if (userEntity == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_NOT_FOUND, Errors.MSG_USER_NOT_FOUND);
			}

			Query<Entity> tokenQuery = Query.newEntityQueryBuilder().setKind("Token").build();
			QueryResults<Entity> tokenResults = datastore.run(tokenQuery);

			while (tokenResults.hasNext()) {
				Entity sessionToken = tokenResults.next();
				String tokenUserId = sessionToken.getString("token_username");
				if (request.input.username.equals(tokenUserId)) {
					datastore.delete(sessionToken.getKey());
				}
			}

			datastore.delete(userKey);

			Map<String, Object> data = new LinkedHashMap<>();
			data.put("message", "Account deleted successfully");

			Map<String, Object> response = new LinkedHashMap<>();
			response.put("status", "success");
			response.put("data", data);

			return Response.ok(g.toJson(response)).build();

		} catch (Exception e) {
			LOG.log(Level.SEVERE, e.toString(), e);
			return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}
	}

	@POST
	@Path("/modaccount")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response modifyAccountAttributes(AuthenticatedRequest<ModifyAccountAttributesData> request) {

	    if (request == null || request.input == null || !request.input.isValidModifyAccountAttributes()) {
	        return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_INPUT, Errors.MSG_INVALID_INPUT);
	    }

	    if (request.token == null || !request.token.isValidTokenFormat()) {
	        return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
	    }
	    
	    try {
	        Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(request.token.tokenId);
	        Entity tokenEntity = datastore.get(tokenKey);

	        if (tokenEntity == null) {
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
	        }

	        TokenData storedToken = TokenData.fromEntity(tokenEntity);

	        if (!request.token.matchesStoredToken(storedToken)) {
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
	        }
	        
	        if (System.currentTimeMillis() > storedToken.expiresAt) {
	        	datastore.delete(tokenKey);
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.TOKEN_EXPIRED, Errors.MSG_TOKEN_EXPIRED);
	        }

	        Key targetUserKey = datastore.newKeyFactory().setKind("User").newKey(request.input.username);
	        Entity targetUser = datastore.get(targetUserKey);

	        if (targetUser == null) {
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_NOT_FOUND, Errors.MSG_USER_NOT_FOUND);
	        }

	        String requesterRole = storedToken.role;
	        String requesterUsername = storedToken.username;
	        String targetRole = targetUser.getString("user_role");

	        boolean authorized = false;

	        if ("ADMIN".equals(requesterRole)) {
	            authorized = true;
	        } else if ("USER".equals(requesterRole)) {
	            authorized = requesterUsername.equals(request.input.username);
	        } else if ("BOFFICER".equals(requesterRole)) {
	            authorized = requesterUsername.equals(request.input.username) || "USER".equals(targetRole);
	        }

	        if (!authorized) {
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
	        }

	        Entity.Builder updatedUserBuilder = Entity.newBuilder(targetUser);

	        if (request.input.attributes.phone != null && !request.input.attributes.phone.isBlank()) {
	            updatedUserBuilder.set("user_phone", request.input.attributes.phone);
	        }

	        if (request.input.attributes.address != null && !request.input.attributes.address.isBlank()) {
	            updatedUserBuilder.set("user_address", request.input.attributes.address);
	        }

	        datastore.put(updatedUserBuilder.build());

	        Map<String, Object> data = new LinkedHashMap<>();
	        data.put("message", "Updated successfully");

	        Map<String, Object> response = new LinkedHashMap<>();
	        response.put("status", "success");
	        response.put("data", data);

	        return Response.ok(g.toJson(response)).build();

	    } catch (Exception e) {
	        LOG.log(Level.SEVERE, e.toString(), e);
	        return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
	    }
	}
	
	@POST
	@Path("/showauthsessions")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response showAuthenticatedSessions(AuthenticatedRequest<EmptyInput> request) {

		if (request == null || request.input == null) {
			return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}

		if (request.token == null || !request.token.isValidTokenFormat()) {
		    return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
		}
		
		try {
			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(request.token.tokenId);
			Entity tokenEntity = datastore.get(tokenKey);

			if (tokenEntity == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			TokenData storedToken = TokenData.fromEntity(tokenEntity);

			if (!request.token.matchesStoredToken(storedToken)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			if (System.currentTimeMillis() > storedToken.expiresAt) {
				datastore.delete(tokenKey);
				return errorResponse(Response.Status.BAD_REQUEST, Errors.TOKEN_EXPIRED, Errors.MSG_TOKEN_EXPIRED);
			}

			Key requesterUserKey = datastore.newKeyFactory().setKind("User").newKey(storedToken.username);
			Entity requesterUser = datastore.get(requesterUserKey);

			if (requesterUser == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			if (!"ADMIN".equals(storedToken.role)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
			}

			Query<Entity> query = Query.newEntityQueryBuilder().setKind("Token").build();

			QueryResults<Entity> results = datastore.run(query);

			List<Map<String, Object>> sessions = new ArrayList<>();

			while (results.hasNext()) {
				Entity session = results.next();

				String sessionUsername = session.getString("token_username");
				long expiresAt = session.getLong("token_expirationData");

				if (System.currentTimeMillis() > expiresAt){
					continue;
					}
				
				Map<String, Object> sessionData = new LinkedHashMap<>();
				sessionData.put("tokenId", session.getKey().getName());
				sessionData.put("username", sessionUsername);
				sessionData.put("role", session.getString("token_role"));
				sessionData.put("expiresAt", expiresAt);

				sessions.add(sessionData);
			}

			Map<String, Object> data = new LinkedHashMap<>();
			data.put("sessions", sessions);

			Map<String, Object> response = new LinkedHashMap<>();
			response.put("status", "success");
			response.put("data", data);

			return Response.ok(g.toJson(response)).build();

		} catch (Exception e) {
			LOG.log(Level.SEVERE, e.toString(), e);
			return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}
	}

	@POST
	@Path("/showuserrole")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response showUserRole(AuthenticatedRequest<ShowUserRoleData> request) {

		if (request == null || request.input == null || !request.input.isValid()) {
			return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}

		if (request.token == null || !request.token.isValidTokenFormat()) {
		    return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
		}
		
		try {
			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(request.token.tokenId);
			Entity tokenEntity = datastore.get(tokenKey);

			if (tokenEntity == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			TokenData storedToken = TokenData.fromEntity(tokenEntity);

			if (!request.token.matchesStoredToken(storedToken)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			if (System.currentTimeMillis() > storedToken.expiresAt) {
				datastore.delete(tokenKey);
				return errorResponse(Response.Status.BAD_REQUEST, Errors.TOKEN_EXPIRED, Errors.MSG_TOKEN_EXPIRED);
			}

			Key requesterUserKey = datastore.newKeyFactory().setKind("User").newKey(storedToken.username);
			Entity requesterUser = datastore.get(requesterUserKey);

			if (requesterUser == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			if (!"ADMIN".equals(storedToken.role) && !"BOFFICER".equals(storedToken.role)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
			}

			Key targetUserKey = datastore.newKeyFactory().setKind("User").newKey(request.input.username);
			Entity targetUser = datastore.get(targetUserKey);

			if (targetUser == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_NOT_FOUND, Errors.MSG_USER_NOT_FOUND);
			}

			Map<String, Object> data = new LinkedHashMap<>();
			data.put("username", targetUser.getString("user_username"));
			data.put("role", targetUser.getString("user_role"));

			Map<String, Object> response = new LinkedHashMap<>();
			response.put("status", "success");
			response.put("data", data);

			return Response.ok(g.toJson(response)).build();

		} catch (Exception e) {
			LOG.log(Level.SEVERE, e.toString(), e);
			return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}
	}

	@POST
	@Path("/changeuserrole")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changeUserRole(AuthenticatedRequest<ChangeUserRoleData> request) {

		if (request == null || request.input == null || !request.input.isValidChangeUserRole()) {
			return errorResponse(Response.Status.BAD_REQUEST, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}

		if (request.token == null || !request.token.isValidTokenFormat()) {
		    return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
		}
		
		try {
			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(request.token.tokenId);
			Entity tokenEntity = datastore.get(tokenKey);

			if (tokenEntity == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			TokenData storedToken = TokenData.fromEntity(tokenEntity);
			
			if (System.currentTimeMillis() > storedToken.expiresAt) {
				datastore.delete(tokenKey);
				return errorResponse(Response.Status.BAD_REQUEST, Errors.TOKEN_EXPIRED, Errors.MSG_TOKEN_EXPIRED);
			}
			
			if (!request.token.matchesStoredToken(storedToken)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			if (!"ADMIN".equals(storedToken.role)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
			}

			Key targetUserKey = datastore.newKeyFactory().setKind("User").newKey(request.input.username);
			Entity targetUser = datastore.get(targetUserKey);

			if (targetUser == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_NOT_FOUND, Errors.MSG_USER_NOT_FOUND);
			}

			Entity.Builder updatedUserBuilder = Entity.newBuilder(targetUser);
			updatedUserBuilder.set("user_role", request.input.newRole);
			datastore.put(updatedUserBuilder.build());

			Query<Entity> tokenQuery = Query.newEntityQueryBuilder().setKind("Token").build();
			QueryResults<Entity> tokenResults = datastore.run(tokenQuery);

			while (tokenResults.hasNext()) {
				Entity sessionToken = tokenResults.next();
				String tokenUsername = sessionToken.getString("token_username");

				if (request.input.username.equals(tokenUsername)) {
					datastore.delete(sessionToken.getKey());
				}
			}
			
			Map<String, Object> data = new LinkedHashMap<>();
			data.put("message", "Role updated successfully");

			Map<String, Object> response = new LinkedHashMap<>();
			response.put("status", "success");
			response.put("data", data);

			return Response.ok(g.toJson(response)).build();

		} catch (Exception e) {
			LOG.log(Level.SEVERE, e.toString(), e);
			return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}
	}

	@POST
	@Path("/changeuserpwd")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changeUserPassword(AuthenticatedRequest<ChangeUserPasswordData> request) {

		if (request == null || request.input == null || !request.input.isValidChangeUserPassword()) {
			return errorResponse(Response.Status.BAD_REQUEST, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}

		if (request.token == null || !request.token.isValidTokenFormat()) {
		    return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
		}
		
		try {
			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(request.token.tokenId);
			Entity tokenEntity = datastore.get(tokenKey);

			if (tokenEntity == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			TokenData storedToken = TokenData.fromEntity(tokenEntity);

			if (System.currentTimeMillis() > storedToken.expiresAt) {
				datastore.delete(tokenKey);
				return errorResponse(Response.Status.BAD_REQUEST, Errors.TOKEN_EXPIRED, Errors.MSG_TOKEN_EXPIRED);
			}
			
			if (!request.token.matchesStoredToken(storedToken)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			if (!storedToken.username.equals(request.input.username)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
			}

			Key targetUserKey = datastore.newKeyFactory().setKind("User").newKey(request.input.username);
			Entity targetUser = datastore.get(targetUserKey);

			if (targetUser == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
			}

			String storedPasswordHash = targetUser.getString("user_pwd");
			String receivedOldPasswordHash = DigestUtils.sha512Hex(request.input.oldPassword);
			String newPasswordHash = DigestUtils.sha512Hex(request.input.newPassword);


			if (!storedPasswordHash.equals(receivedOldPasswordHash)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_CREDENTIALS, Errors.MSG_INVALID_CREDENTIALS);
			}
			
			
			if(storedPasswordHash.equals(newPasswordHash)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
			}

			Entity.Builder updatedUserBuilder = Entity.newBuilder(targetUser);
			updatedUserBuilder.set("user_pwd", DigestUtils.sha512Hex(request.input.newPassword));
			datastore.put(updatedUserBuilder.build());

			Map<String, Object> data = new LinkedHashMap<>();
			data.put("message", "Password changed successfully");

			Map<String, Object> response = new LinkedHashMap<>();
			response.put("status", "success");
			response.put("data", data);

			return Response.ok(g.toJson(response)).build();

		} catch (Exception e) {
			LOG.log(Level.SEVERE, e.toString(), e);
			return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
		}
	}

	@POST
	@Path("/logout")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response logout(AuthenticatedRequest<LogoutData> request) {

	    if (request == null || request.input == null || !request.input.isValidLogout()) {
	        return errorResponse(Response.Status.BAD_REQUEST, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
	    }

	    if (request.token == null || !request.token.isValidTokenFormat()) {
	        return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
	    }

	    try {
	        Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(request.token.tokenId);
	        Entity tokenEntity = datastore.get(tokenKey);

	        if (tokenEntity == null) {
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
	        }

	        TokenData storedToken = TokenData.fromEntity(tokenEntity);

	        if (!request.token.matchesStoredToken(storedToken)) {
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
	        }

	        if (System.currentTimeMillis() > storedToken.expiresAt) {
	            datastore.delete(tokenKey);
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.TOKEN_EXPIRED, Errors.MSG_TOKEN_EXPIRED);
	        }

	        boolean isAdmin = "ADMIN".equals(storedToken.role);
	        boolean isOwnAccount = storedToken.username.equals(request.input.username);

	        if (!isAdmin && !isOwnAccount) {
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
	        }

	        if (isOwnAccount) {
	            datastore.delete(tokenKey);
	        } else {
	            Query<Entity> query = Query.newEntityQueryBuilder()
	                    .setKind("Token")
	                    .build();

	            QueryResults<Entity> results = datastore.run(query);

	            boolean deletedAny = false;

	            while (results.hasNext()) {
	                Entity sessionToken = results.next();
	                String tokenUsername = sessionToken.getString("token_username");

	                if (request.input.username.equals(tokenUsername)) {
	                    datastore.delete(sessionToken.getKey());
	                    deletedAny = true;
	                }
	            }

	            if (!deletedAny) {
	                return errorResponse(Response.Status.BAD_REQUEST, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
	            }
	        }

	        Map<String, Object> data = new LinkedHashMap<>();
	        data.put("message", "Logout successful");

	        Map<String, Object> response = new LinkedHashMap<>();
	        response.put("status", "success");
	        response.put("data", data);

	        return Response.ok(g.toJson(response)).build();

	    } catch (Exception e) {
	        LOG.log(Level.SEVERE, e.toString(), e);
	        return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, Errors.FORBIDDEN, Errors.MSG_FORBIDDEN);
	    }
	}
	
	private Response errorResponse(Response.Status status, String errorCode, String message) {
		Map<String, Object> response = new LinkedHashMap<>();
		response.put("status", errorCode);
		response.put("data", message);

		return Response.ok(g.toJson(response)).build();
	}
}