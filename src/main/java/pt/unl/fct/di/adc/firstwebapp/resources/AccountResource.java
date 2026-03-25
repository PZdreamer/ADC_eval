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
//import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
//import jakarta.ws.rs.PathParam;
//import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
//import jakarta.ws.rs.core.Response.Status;
import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Key;
//import com.google.cloud.datastore.KeyFactory;
//import com.google.cloud.datastore.PathElement;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreException;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.gson.Gson;

import pt.unl.fct.di.adc.firstwebapp.util.AuthToken;
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

	private static final Datastore datastore = DatastoreOptions.newBuilder().setProjectId("adc-pei-2526").build()
			.getService();

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
				return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_ALREADY_EXISTS,
						Errors.MSG_USER_ALREADY_EXISTS);
			}

			Entity accountEntity = Entity.newBuilder(userKey).set("user_username", account.username)
					.set("user_pwd", DigestUtils.sha512Hex(account.password)).set("user_phone", account.phone)
					.set("user_address", account.address).set("user_role", account.role)
					.set("user_creation_time", Timestamp.now()).build();

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
			return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_INPUT, Errors.MSG_INVALID_INPUT);
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

			AuthToken token = new AuthToken(login.username);
			String role = userEntity.getString("user_role");

			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(token.tokenID);

			Entity tokenEntity = Entity.newBuilder(tokenKey).set("token_id", token.tokenID)
					.set("token_username", token.username).set("token_creationData", token.creationData)
					.set("token_expirationData", token.expirationData).set("token_role", role).build();

			datastore.put(tokenEntity);

			Map<String, Object> tokenData = new LinkedHashMap<>();
			tokenData.put("tokenId", token.tokenID);
			tokenData.put("username", token.username);
			tokenData.put("role", role);
			tokenData.put("issuedAt", token.creationData);
			tokenData.put("expiresAt", token.expirationData);

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

		if (request == null || request.input == null || request.token == null || !request.token.isValidTokenFormat()) {
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

		if (request == null || request.input == null || !request.input.isValidDeleteAccount() || request.token == null
				|| !request.token.isValidTokenFormat()) {
			return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_INPUT, Errors.MSG_INVALID_INPUT);
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
				datastore.delete(tokenKey);
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
			}

			if (!"ADMIN".equals(storedToken.role)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
			}

			Key userKey = datastore.newKeyFactory().setKind("User").newKey(request.input.userId);
			Entity userEntity = datastore.get(userKey);

			if (userEntity == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_NOT_FOUND, Errors.MSG_USER_NOT_FOUND);
			}

			Query<Entity> tokenQuery = Query.newEntityQueryBuilder().setKind("Token").build();

			QueryResults<Entity> tokenResults = datastore.run(tokenQuery);

			while (tokenResults.hasNext()) {
				Entity sessionToken = tokenResults.next();

				String tokenUserId = sessionToken.getString("token_username");

				if (request.input.userId.equals(tokenUserId)) {
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
	@Path("/modifyaccountattributes")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response modifyAccountAttributes(AuthenticatedRequest<ModifyAccountAttributesData> request) {

	    if (request == null || request.input == null || !request.input.isValidModifyAccountAttributes()
	            || request.token == null || !request.token.isValidTokenFormat()) {
	        return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_INPUT, Errors.MSG_INVALID_INPUT);
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
	@Path("/showsessions")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response showAuthenticatedSessions(AuthenticatedRequest<EmptyInput> request) {

		if (request == null || request.input == null || request.token == null || !request.token.isValidTokenFormat()) {
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

			// If manually deletion of users occur but the token persists
			if (System.currentTimeMillis() > storedToken.expiresAt) {
				datastore.delete(tokenKey);
				return errorResponse(Response.Status.BAD_REQUEST, Errors.TOKEN_EXPIRED, Errors.MSG_TOKEN_EXPIRED);
			}

			Key requesterUserKey = datastore.newKeyFactory().setKind("User").newKey(storedToken.username);
			Entity requesterUser = datastore.get(requesterUserKey);

			if (requesterUser == null) {
				datastore.delete(tokenKey);
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

				if (System.currentTimeMillis() > expiresAt) {
					datastore.delete(session.getKey());
					continue;
				}

				Key sessionUserKey = datastore.newKeyFactory().setKind("User").newKey(sessionUsername);
				Entity sessionUser = datastore.get(sessionUserKey);

				if (sessionUser == null) {
					datastore.delete(session.getKey());
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

		if (request == null || request.input == null || !request.input.isValidUserRole() || request.token == null || !request.token.isValidTokenFormat()) {
			return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_INPUT, Errors.MSG_INVALID_INPUT);
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

			// If manually deletion of users occur but the token persists
			if (requesterUser == null) {
				datastore.delete(tokenKey);
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

		if (request == null || request.input == null || !request.input.isValidChangeUserRole() || request.token == null
				|| !request.token.isValidTokenFormat()) {
			return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_INPUT, Errors.MSG_INVALID_INPUT);
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

			Key targetUserKey = datastore.newKeyFactory().setKind("User").newKey(request.input.username);
			Entity targetUser = datastore.get(targetUserKey);

			if (targetUser == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_NOT_FOUND, Errors.MSG_USER_NOT_FOUND);
			}

			Entity.Builder updatedUserBuilder = Entity.newBuilder(targetUser);
			updatedUserBuilder.set("user_role", request.input.newRole);
			datastore.put(updatedUserBuilder.build());

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
	@Path("/changeuserpassword")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changeUserPassword(AuthenticatedRequest<ChangeUserPasswordData> request) {

		if (request == null || request.input == null || !request.input.isValidChangeUserPassword()
				|| request.token == null || !request.token.isValidTokenFormat()) {
			return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_INPUT, Errors.MSG_INVALID_INPUT);
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

			if (!storedToken.username.equals(request.input.username)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
			}

			Key targetUserKey = datastore.newKeyFactory().setKind("User").newKey(request.input.username);
			Entity targetUser = datastore.get(targetUserKey);

			if (targetUser == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_NOT_FOUND, Errors.MSG_USER_NOT_FOUND);
			}

			String targetStoredPasswordHash = targetUser.getString("user_pwd");
			String receivedOldPasswordHash = DigestUtils.sha512Hex(request.input.oldPassword);

			if (!targetStoredPasswordHash.equals(receivedOldPasswordHash)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_CREDENTIALS,
						Errors.MSG_INVALID_CREDENTIALS);
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

		if (request == null || request.input == null || !request.input.isValidLogout() || request.token == null
				|| !request.token.isValidTokenFormat()) {
			return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_INPUT, Errors.MSG_INVALID_INPUT);
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

			if (!"ADMIN".equals(storedToken.role) && !storedToken.username.equals(request.input.username)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
			}

			Query<Entity> query = Query.newEntityQueryBuilder().setKind("Token").build();

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
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_TOKEN, Errors.MSG_INVALID_TOKEN);
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

		return Response.status(status).entity(g.toJson(response)).build();
	}
}