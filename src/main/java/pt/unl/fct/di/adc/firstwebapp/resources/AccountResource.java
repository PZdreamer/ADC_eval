package pt.unl.fct.di.adc.firstwebapp.resources;

//import java.sql.Time;
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
import pt.unl.fct.di.adc.firstwebapp.util.CreateAccount;
import pt.unl.fct.di.adc.firstwebapp.util.Errors;
import pt.unl.fct.di.adc.firstwebapp.util.LoginData;
import pt.unl.fct.di.adc.firstwebapp.util.ModifyAccountAttributesData;
import pt.unl.fct.di.adc.firstwebapp.util.DeleteAccountData;
import pt.unl.fct.di.adc.firstwebapp.util.EmptyInput;
import pt.unl.fct.di.adc.firstwebapp.util.OperationRequest;
import pt.unl.fct.di.adc.firstwebapp.util.TokenData;

@Path("/")
public class AccountResource {

	private static final Logger LOG = Logger.getLogger(AccountResource.class.getName());

	// private static final Datastore datastore =
	// DatastoreOptions.getDefaultInstance().getService();
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
					.set("user_pwd", DigestUtils.sha512Hex(account.password)).set("user_email", account.email)
					.set("user_phone", account.phone).set("user_address", account.address)
					.set("user_role", account.role).set("user_creation_time", Timestamp.now()).build();

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
				return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_CREDENTIALS,
						Errors.MSG_INVALID_CREDENTIALS);
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
			tokenData.put("userId", token.username);
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
				userData.put("userId", user.getKey().getName());
				userData.put("username", user.getString("user_username"));
				userData.put("email", user.getString("user_email"));
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

			if (!"ADMIN".equals(storedToken.role)) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
			}

			Key userKey = datastore.newKeyFactory().setKind("User").newKey(request.input.userId);
			Entity userEntity = datastore.get(userKey);

			if (userEntity == null) {
				return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_NOT_FOUND, Errors.MSG_USER_NOT_FOUND);
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
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.TOKEN_EXPIRED, Errors.MSG_TOKEN_EXPIRED);
	        }

	        Key targetUserKey = datastore.newKeyFactory().setKind("User").newKey(request.input.userId);
	        Entity targetUser = datastore.get(targetUserKey);

	        if (targetUser == null) {
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.USER_NOT_FOUND, Errors.MSG_USER_NOT_FOUND);
	        } 

	        String currentUsername = targetUser.getString("user_username");

	        if (request.input.attributes.username != null
	                && !request.input.attributes.username.isBlank()
	                && !request.input.attributes.username.equals(currentUsername)) {
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.INVALID_INPUT, Errors.MSG_INVALID_INPUT);
	        }

	        String requesterRole = storedToken.role;
	        String requesterUserId = storedToken.userId;
	        String targetRole = targetUser.getString("user_role");

	        boolean authorized = false;

	        if ("ADMIN".equals(requesterRole)) {
	            authorized = true;
	        } else if ("USER".equals(requesterRole)) {
	            authorized = requesterUserId.equals(request.input.userId);
	        } else if ("BOFFICER".equals(requesterRole)) {
	            authorized = requesterUserId.equals(request.input.userId) || "USER".equals(targetRole);
	        }

	        if (!authorized) {
	            return errorResponse(Response.Status.BAD_REQUEST, Errors.UNAUTHORIZED, Errors.MSG_UNAUTHORIZED);
	        }

	        Entity.Builder updatedUserBuilder = Entity.newBuilder(targetUser);

	        if (request.input.attributes.email != null && !request.input.attributes.email.isBlank()) {
	            updatedUserBuilder.set("user_email", request.input.attributes.email);
	        }

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

	private Response errorResponse(Response.Status status, String errorCode, String message) {
		Map<String, Object> response = new LinkedHashMap<>();
		response.put("status", errorCode);
		response.put("data", message);

		return Response.status(status).entity(g.toJson(response)).build();
	}
}