package pt.unl.fct.di.adc.firstwebapp.resources;

import java.sql.Time;
import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import pt.unl.fct.di.adc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.adc.firstwebapp.util.LoginData;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.PathElement;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.gson.Gson;


@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

	/** 
	 * Logger Object
	 */
	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private static final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");

	private final Gson g = new Gson();
	
	public LoginResource() {} // Nothing to be done here
	
	@POST
	@Path("/")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doLogin(LoginData data) {
		LOG.fine("Attempt to login user: " + data.username);

		if(data.username.equals("user") && data.password.equals("password")) {
			AuthToken at = new AuthToken(data.username);
			return Response.ok(g.toJson(at)).build();
		}

		return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
		
	}
	
	@GET
	@Path("/{username}")
	public Response checkUsernameAvailable(@PathParam("username") String username) {
		if(username.trim().equals("user")) {
			return Response.ok().entity(g.toJson(false)).build();
		} else {
			return Response.ok().entity(g.toJson(true)).build();
		}
	}

	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doLoginV1(LoginData data) {
		LOG.fine("Attempt to login user: " + data.username);

		Key userKey = userKeyFactory.newKey(data.username);
		Entity user = datastore.get(userKey);

		if(user != null) {
			String hashedPWD = user.getString("user_pwd");
			if(hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {
				LOG.info("User '" + data.username + "' logged in successfully.");
				AuthToken at = new AuthToken(data.username);
				return Response.ok(g.toJson(at)).build();
			}
			else {
				LOG.warning("User '" + data.username + "' provided wrong password.");
				return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
			}
		}
		else {
			LOG.warning("User '" + data.username + "' does not exist.");
			return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
		}
	}

	@POST
	@Path("/v1a")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doLoginV1a(LoginData data) {
		LOG.fine("Attempt to login user: " + data.username);

		Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
		Entity user = datastore.get(userKey);

		if(user != null) {
			String hashedPWD = user.getString("user_pwd");
			if(hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {
				LOG.info("User '" + data.username + "' logged in successfully.");
				user = Entity.newBuilder(user)
						.set("user_login_time", Timestamp.now())
						.build();
				datastore.update(user);
				AuthToken at = new AuthToken(data.username);
				return Response.ok(g.toJson(at)).build();
			}
			else {
				LOG.warning("User '" + data.username + "' provided wrong password.");
				return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
			}
		}
		else {
			LOG.warning("User '" + data.username + "' does not exist.");
			return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
		}
	}

	@POST@Path("/v1b")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response doLoginV1b(LoginData data) {
		LOG.fine("Attempt to login user: " + data.username);

		Key userKey = userKeyFactory.newKey(data.username);
		Entity user = datastore.get(userKey);
		
		if( user != null ) {
			String hashedPWD = user.getString("user_pwd");
			if( hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {
				KeyFactory logKeyFactory = datastore.newKeyFactory()
						.addAncestor(PathElement.of("User", data.username))
						.setKind("UserLog");
				Key logKey = datastore.allocateId(logKeyFactory.newKey());
				Entity userLog = Entity.newBuilder(logKey)
						.set("user_login_time", Timestamp.now())
						.build();
				datastore.put(userLog);
				LOG.info("User '" + data.username + "' logged in successfuly.");
				AuthToken token = new AuthToken(data.username);
				return Response.ok(g.toJson(token)).build();
			}
			else {
				LOG.warning("Wrong password for: " + data.username);
				return Response.status(Status.FORBIDDEN).build();
			}
		}
		else {
			LOG.warning("Failed login attempt for username: " + data.username);
			return Response.status(Status.FORBIDDEN).build();
		}
	}
}