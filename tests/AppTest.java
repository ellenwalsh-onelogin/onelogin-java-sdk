package com.onelogin.sdk;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.codec.digest.DigestUtils;
import com.onelogin.sdk.conn.org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import com.onelogin.sdk.conn.org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.xml.sax.SAXException;

import com.onelogin.sdk.conn.Client;
import com.onelogin.sdk.conn.OneLoginResponse;
import com.onelogin.sdk.exception.Error;
import com.onelogin.sdk.exception.ErrorResourceInitialization;
import com.onelogin.sdk.model.App;
import com.onelogin.sdk.model.AssignedApp;
import com.onelogin.sdk.model.AssignedUser;
import com.onelogin.sdk.model.AssignedAdmin;
import com.onelogin.sdk.model.AuthFactor;
import com.onelogin.sdk.model.Event;
import com.onelogin.sdk.model.EventType;
import com.onelogin.sdk.model.FactorEnrollmentResponse;
import com.onelogin.sdk.model.Group;
import com.onelogin.sdk.model.MFA;
import com.onelogin.sdk.model.MFACheckStatus;
import com.onelogin.sdk.model.MFAToken;
import com.onelogin.sdk.model.Mapping;
import com.onelogin.sdk.model.OneLoginApp;
import com.onelogin.sdk.model.OTPDevice;
import com.onelogin.sdk.model.Privilege;
import com.onelogin.sdk.model.RateLimit;
import com.onelogin.sdk.model.Role;
import com.onelogin.sdk.model.SAMLEndpointResponse;
import com.onelogin.sdk.model.SessionToken;
import com.onelogin.sdk.model.SessionTokenInfo;
import com.onelogin.sdk.model.SessionTokenMFAInfo;
import com.onelogin.sdk.model.Statement;
import com.onelogin.sdk.model.User;


public class AppTest
{
    public static void main( String[] args ) throws IOException, OAuthSystemException, OAuthProblemException, ErrorResourceInitialization, URISyntaxException, NoSuchMethodException
    {
//    	Client client = new Client();
//    	String ip = client.getIP();

//    	Client client = new Client("<edited_client_id>", "<edited_client_secret>", "us");

    	Map<String, Integer> api_configuration = new HashMap<String, Integer>();
    	api_configuration.put("role", 2);
    	api_configuration.put("group", 1);
    	api_configuration.put("user", 2);
    	api_configuration.put("app", 1);
    	api_configuration.put("mfa", 2);
    	api_configuration.put("assertion", 1);
    	
//    	Client client = new Client("<edited_client_id>", "<edited_client_secret>", "TODO", api_configuration, false);

		Client client = new Client("<edited_client_id>", "<edited_client_secret>", "sixtoprod-us", api_configuration, false);

//    	Client client = new Client("<edited_client_id>", "<edited_client_secret>", "us");
    	
    	
    	client.getAccessToken();
    	
    	
    	//List<Role> roles = client.getRoles();
    	Role roleX = client.getRole(494297L);
    	List <AssignedApp> appRoles = client.getRoleApps(494297L, false);
    	List <AssignedUser> appUsers = client.getRoleUsers(494297L, null, true);
    	List <AssignedAdmin> appAdmins = client.getRoleAdmins(494297L, null, true);
    	
//    	List<Long> roleAppIdsToAssign = new ArrayList<Long>();
//    	roleAppIdsToAssign.add(1110783L);
//    	List<Long> assignedAppIds = client.setRoleApps(494297L, roleAppIdsToAssign);
    	roleX = client.getRole(494297L);

    	List<Long> roleUserIdsToAssign = new ArrayList<Long>();
    	roleUserIdsToAssign.add(150108233L);
    	//List<Long> assignedUserIds = client.addRoleUsers(494297L, roleUserIdsToAssign);
    	//roleX = client.getRole(494297L);
    	
    	List<Long> roleAdminIdsToAssign = new ArrayList<Long>();
    	roleAdminIdsToAssign.add(117844919L);
    	//List<Long> assignedAdminIds = client.addRoleAdmins(494297L, roleAdminIdsToAssign);
    	//roleX = client.getRole(494297L);
    	
    	client.removeRoleUsers(494297L, roleUserIdsToAssign);
    	client.removeRoleAdmins(494297L, roleAdminIdsToAssign);
    	roleX = client.getRole(494297L);
    	
    	
    	// TODO
    	// Probar addRoleUsers, removeRoleUsers, addRoleAdmins, removeRoleAdmins
    	
/*
    	List<Long> roleUserIds = new ArrayList<Long>();
    	List<Long> roleAdminIds = new ArrayList<Long>();
    	List<Long> roleAppIds = new ArrayList<Long>();
    	
    	
    	Map<String, Object> newRoleParams = new HashMap<String, Object>();
    	newRoleParams.put("name", "RoleApiTest1");
    	newRoleParams.put("apps", roleAppIds);
    	newRoleParams.put("users", roleUserIds);
    	newRoleParams.put("admins", roleAdminIds);
    	Long newRoleId = client.createRole(newRoleParams);
    	
    	Role newRole = client.getRole(newRoleId);
    	
    	roleAppIds.add(1110783L);
    	roleUserIds.add(150108233L);
    	roleAdminIds.add(117844919L);
    	newRoleParams.put("name", "RoleApiTest1 updated");
    	newRoleParams.put("apps", roleAppIds);
    	newRoleParams.put("users", roleUserIds);
    	newRoleParams.put("admins", roleAdminIds);
    	Long updatedRoleId = client.updateRole(newRoleId, newRoleParams);
    	Role updatedRole = client.getRole(updatedRoleId);
    	Boolean deletedRole = client.deleteRole(updatedRoleId);
    	updatedRole = client.getRole(updatedRoleId);
*/


    	List<User> usersxxx = client.getUsers(10);
    	List<OneLoginApp> appsx2 = client.getApps(5);

    	//FactorEnrollmentResponse factorEnroll2 = client.activateFactor(63900653, 8851136);
    	//Boolean rr = client.verifyFactor(63900653, 8851136, "472340", "b146c7bcc0aa5bb6b25724e245be8420d3df7902");

    	//List<AuthFactor> authFactors = client.getFactors(usersxxx.get(4).id);

    	//OTPDevice otpDevice = client.enrollFactor(63900653, 76227, "Protect API", null, false, null, null);

    	//FactorEnrollmentResponse fresponse = client.activateFactor(63900653, "fe8c74d3-312a-4138-9ede-d4a8a1b1f662", null, null);
    	//MFACheckStatus check = client.verifyEnrollFactorOtp(63900653, "fe8c74d3-312a-4138-9ede-d4a8a1b1f662", "68B674");
    	//MFACheckStatus check2 = client.verifyEnrollFactorPoll(63900653, "fe8c74d3-312a-4138-9ede-d4a8a1b1f662");
    	
    	//Boolean res = verifyFactor(63900653, "", String otpToken, String stateToken)
    	
    	// authFactors = client.getFactors(usersxxx.get(4).id);
    	
    	//OTPDevice otpDevice = client.enrollFactor(usersxxx.get(4).id, authFactors.get(1).getID(), "XX Factor Name X", null, false, null, null);

    	List<OTPDevice> enrolledFactors = client.getEnrolledFactors(usersxxx.get(4).id);

    	//FactorEnrollmentResponse factorEnroll = client.activateFactor(usersxxx.get(4).id, enrolledFactors.get(1).id);
    	
    	//Boolean rest = client.removeFactor(usersxxx.get(4).id, enrolledFactors.get(1).id);
    	
    	Boolean rii = client.verifyFactorOtp(63900653, "49cc0570-7a77-481f-98dd-9046845e34be", "B0DA58", 8854255);
    	// MFAToken mfaToken2 = client.generateMFAToken(usersxxx.get(4).id, 666, true);
    	
    	Map<String, Object> newMapParams = new HashMap<String, Object>();
    	newMapParams.put("name", "My Fiest Mapping");
    	newMapParams.put("match", "all");
    	newMapParams.put("enabled", true);
    	newMapParams.put("position", "null");
    	newMapParams.put("enabled", true);
    	newMapParams.put("conditions", null);
    	newMapParams.put("actions", null);
    	
        Mapping createdMapping = client.createMapping(newMapParams);
    	

//    	List<EventType> eventTypes = client.getEventTypes();
    	
/*
    	Map<String, Object> newUserParams = new HashMap<String, Object>();
        newUserParams.put("email", "testcreate_25@example.com");
        newUserParams.put("firstname", "testcreate_25_fn");
        newUserParams.put("lastname", "testcreate_25_ln");
        newUserParams.put("username", "testcreate_25@example.com");
        User createdUser = client.createUser(newUserParams);
*/
    	
    	
/*    	
        User newUser = client.getUser(151771569);

    	List<App> userApps = client.getUserApps(newUser.id);
    	
    	List<Long> userRoles = client.getUserRoles(newUser.id);
    	
    	List<OneLoginApp> apps = client.getApps(5);
    	
    	//List<Role> roles = client.getRoles();
    	
    	List<Long> rolesToAssign = new ArrayList<Long>();
    	rolesToAssign.add(167861L);
    	rolesToAssign.add(170001L);
    	rolesToAssign.add(176129L);
    	List<Long> rolesToRemove = new ArrayList<Long>();
    	rolesToRemove.add(176129L);
    	boolean result = client.assignRoleToUser(newUser.id, rolesToAssign);
    	userRoles = client.getUserRoles(newUser.id);
    	result = client.removeRoleFromUser(newUser.id, rolesToRemove);
    	userRoles = client.getUserRoles(newUser.id);
*/
/*
    	HashMap<String, String> searchUserParams = new HashMap<String, String>();
    	searchUserParams.put("email", "*freeradius*");
    	List<User> selectedUsers = client.getUsers(searchUserParams);
*/
    	
    	//SAMLEndpointResponse samlEndpointResponse = client.getSAMLAssertion("test_freeradius@example.com", "<edited_pw>", "643881", "TODO");
    	/*SAMLEndpointResponse samlEndpointResponse = client.getSAMLAssertion("testlogin@example.com", "<edited_pw>", "1068583", "sixtoprod-us");
    	
    	if (samlEndpointResponse.getMFA() != null) {
    		MFA mfa = samlEndpointResponse.getMFA();
    		String otpToken = "ccccccbcicbgchtllevlreinbvfirkgkhkcckuktdtvn";
    		samlEndpointResponse = client.getSAMLAssertionVerifying("1068583", Long.toString(mfa.getDevices().get(3).getID()), mfa.getStateToken(), otpToken);
    	}
*/

// app id 595390
// role ids 167861 170001 176129    	
    	

/*    	
    	String invitation = client.generateInviteLink("xxx@example.com");
    	boolean result = client.sendInviteLink("xxx@example.com", null);
*/  	
        
/*
    	Map<String, Object> session_login_token_params = new HashMap<String, Object>();
        session_login_token_params.put("username_or_email", "test_freeradius@example.com");
        session_login_token_params.put("password", "<edited_pw>");
        session_login_token_params.put("subdomain", "TODO");

        SessionToken session_token_data = client.createSessionLoginToken(session_login_token_params);
        SessionTokenMFAInfo session_token_data_mfa;
        SessionTokenInfo session_token_data_info;
        
        if (session_token_data == null) {
        	System.out.println(client.getErrorDescription());
        } else if (session_token_data.requireMFA()) {
        	session_token_data_mfa = (SessionTokenMFAInfo) session_token_data;
        	String otpToken = "ccccccbcicbgrgchknjendthhkdeeufttlfdiivkuucf";
        	session_token_data = client.getSessionTokenVerified(session_token_data_mfa.getDevices().get(1).getID(), session_token_data_mfa.getStateToken(), otpToken);
        	if (session_token_data == null) {
            	System.out.println(client.getErrorDescription());
            } else {
            	session_token_data_info = (SessionTokenInfo) session_token_data;
            	String sessionToken = session_token_data_info.getSessionToken();
        	}
        } else {
        	session_token_data_info = (SessionTokenInfo) session_token_data;
        }
*/
       

    	List<OneLoginApp> olApps = client.getApps(20);
    	

//    	MFAToken mfa = client.generateMFAToken(31669586);

/*
        Map<String, Object> newUserParams = new HashMap<String, Object>();
        newUserParams.put("email", "testcreate_15@example.com");
        newUserParams.put("firstname", "testcreate_15_fn");
        newUserParams.put("lastname", "testcreate_15_ln");
        newUserParams.put("username", "testcreate_15@example.com");
        User createdUser = client.createUser(newUserParams);
*/

/*
        newUserParams.put("firstname", "testcreate_15x_fn");
        newUserParams.put("lastname", "testcreate_15x_ln");
        User updatedUser = client.updateUser(createdUser.id, newUserParams);
*/

		RateLimit rl = client.getRateLimit();

    	User usery = client.getUser(27030376);


    	OneLoginResponse<User> x = client.getUsersBatch(10 );
    	List<Long> theUserIds = new ArrayList<Long>();
    	for (User user: (List<User>) x.getResults()) {
    		theUserIds.add(user.id);
    	}
/*
    	while (x.getAfterCursor() != null) {
    		x = client.getUsersBatch(5, x.getAfterCursor());
    		for (User user: (List<User>) x.getResults()) {
        		theUserIds.add(user.id);
        	}    		
    	}
*/

    	List<Event> events = client.getEvents();
    	Event event = client.getEvent(events.get(0).id);


    	List<Group> groups = client.getGroups();
    	Group group = client.getGroup(groups.get(0).getID());

//    	List<Role> roles = client.getRoles();
//    	Role role = client.getRole(167861);

//    	List<Integer> roleIds = client.getUserRoles(37321818);
//    	List<App> userApps = client.getUserApps(27030376);

    	//User userx = client.getUser(138442511);

    	HashMap <String, String> queryUser = new HashMap<String, String>();
    	queryUser.put("username", "test2*");
/*
    	OneLoginResponse<User> x2 = client.getUsersBatch(queryUser, 1);
    	x2 = client.getUsersBatch(1, x2.getAfterCursor());
    	x2 = client.getUsersBatch(1, x2.getAfterCursor());
*/
    	
    	// Role role = client.getRole(167861);

    	List<String> custom_attributes = client.getCustomAttributes();

    	List<User> users = client.getUsers(queryUser);
    	List<Long> userIds = new ArrayList<Long>();
    	for(User user: users) {
    		userIds.add(user.id);
    	}

    	User user = client.getUser(userIds.get(1));

    	Map <String, Object> custom = new HashMap<String, Object>();
    	custom.put("VBU", "ZN");
    	Boolean res = client.setCustomAttributeToUser(user.id, custom);

    	if (res != true) {
    		String a = "1";
    	}

    	User user2 = client.getUser(userIds.get(0));
    	
    	List<OneLoginApp> apps2 = client.getApps(20);
    	
    	MFAToken mfaToken = client.generateMFAToken(37371998, 60, true);
    	
    	List<Privilege> privileges = client.getPrivileges();

    	Privilege privilege = client.getPrivilege(privileges.get(0).id);
    	
    	for (Privilege priv: privileges) {
    		client.deletePrivilege(priv.id);
    	}
/*
    	String name = "privilege_example";
    	String version = "2018-05-18";

    	Statement statement1 = new Statement(
    	    "Allow",
    	    Arrays.asList(
    	        "users:List",
    	        "users:Get"
    	    ),
    	    Arrays.asList("*")
    	);

    	Statement statement2 = new Statement(
    	    "Allow",
    	    Arrays.asList(
    	        "apps:List",
    	        "apps:Get"
    	    ),
    	    Arrays.asList("*")
    	);

    	List<Statement> statements = Arrays.asList(statement1, statement2);
*/
    	/*
    	Map<String, Object> statement1 = new HashMap<String, Object>();
    	statement1.put("Effect", "Allow");
    	statement1.put("Action", Arrays.asList(
    	        "users:List",
    	        "users:Get"
    	));
    	statement1.put("Scope", Arrays.asList("*"));
    	
    	Map<String, Object> statement2 = new HashMap<String, Object>();
    	statement2.put("Effect", "Allow");
    	statement2.put("Action", Arrays.asList(
    	        "apps:List",
    	        "apps:Get"
    	));
    	statement2.put("Scope", Arrays.asList("*"));

    	List<Map<String, Object>> statements = Arrays.asList(statement1, statement2);
*/

//    	Privilege newPrivilege = client.createPrivilege(name, version, statements);

/*
    	statement2.put("Action", Arrays.asList(
    	        "apps:List"
    	));
    	statements = Arrays.asList(statement1, statement2);
    	name = "modified_privilege_example";
    	
    	
    	privileges = client.getPrivileges();
    	Privilege privilege2 = client.updatePrivilege(privileges.get(0).id, name, version, statements);

    	privileges = client.getPrivileges();
*/
/*    	
    	List<Role> roles = client.getRoles();
    	List<Long> roleIds = new ArrayList<Long>();
    	for(Role role: roles) {
    		roleIds.add(role.getID());
    	}
    	
    	boolean result = client.assignRolesToPrivilege(privilege.id, roleIds);
    	
    	List<Long> roleIds2 = client.getRolesAssignedToPrivileges(privilege.id);
    	
    	client.removeRoleFromPrivilege(privilege.id, roleIds2.get(0));
    	
    	List<Long> roleIds3 = client.getRolesAssignedToPrivileges(privilege.id);
*/

    	boolean result2 = client.assignUsersToPrivilege(privilege.id, userIds);

    	List<Long> userIds2 = client.getUsersAssignedToPrivileges(privilege.id);
    	
    	client.removeUserFromPrivilege(privilege.id, userIds2.get(0));
    	
    	List<Long> userIds3 = client.getUsersAssignedToPrivileges(privilege.id);
    	
//    	SAMLEndpointResponse saml_endpoint_response2 = client.getSAMLAssertion("test_freeradius@example.com", "<edited_pw>", "614161", "TODO");
    	
//    	client.revokeToken();
//    	client.refreshToken();

/*    	
    	SAMLEndpointResponse saml_endpoint_response2 = client.getSAMLAssertion("test_freeradius@example.com", "<edited_pw>", "614161", "TODO");
    	
    	MFA mfa = saml_endpoint_response2.getMFA();
    	SAMLEndpointResponse saml_endpoint_response_after_verify = client.getSAMLAssertionVerifying("614161", String.valueOf(mfa.getDevices().get(0).getID()) , mfa.getStateToken());
    	saml_endpoint_response_after_verify = client.getSAMLAssertionVerifying("614161", String.valueOf(mfa.getDevices().get(0).getID()), mfa.getStateToken(), null, null, false);
    	saml_endpoint_response_after_verify = client.getSAMLAssertionVerifying("614161", String.valueOf(mfa.getDevices().get(0).getID()), mfa.getStateToken(), null, null, true);

        Map<String, Object> session_login_token_params = new HashMap<String, Object>();
        session_login_token_params.put("username_or_email", "test_freeradius@example.com");
        session_login_token_params.put("password", "1test_freeradius@example.com!");
        session_login_token_params.put("subdomain", "TODO");
        
        SessionToken session_token_data = client.createSessionLoginToken(session_login_token_params);

        SessionToken info = client.getSessionTokenVerified(String.valueOf(session_token_data.getDevices().get(0).getID()), session_token_data.getStateToken(), null, null);

        info = client.getSessionTokenVerified(String.valueOf(session_token_data.getDevices().get(0).getID()), session_token_data.getStateToken(), null, null, false);

        info = client.getSessionTokenVerified(String.valueOf(session_token_data.getDevices().get(0).getID()), session_token_data.getStateToken(), null, null, true);
*/


//        client.getAccessToken();

//       List<AuthFactor> authFactors = client.getFactors(35962095);

        //OTPDevice res = client.enrollFactor(00, 00, "..", "..");
//        List<OTPDevice> res = client.getEnrolledFactors(35962095);


/*    	
        HashMap<String, String> userQueryParameters = new HashMap<String, String>();
        userQueryParameters.put("limit", "10");
        List<User> users = client.getUsers(userQueryParameters);
//        List<User> users = client.getUsers();
    	
        List<Role> roles = client.getRoles();

        HashMap<String, String> eventQueryParameters = new HashMap<String, String>();
        eventQueryParameters.put("event_type_id", "149");
        eventQueryParameters.put("limit", "51");
        List<Event> filteredEvents = client.getEvents(eventQueryParameters);

        List<Group> groups = client.getGroups();
*/
/*    	
        Map<String, Object> newUserParams = new HashMap<String, Object>();
        newUserParams.put("email", "testcreate_1@example.com");
        newUserParams.put("firstname", "testcreate_1_fn");
        newUserParams.put("lastname", "testcreate_1_ln");
        newUserParams.put("username", "testcreate_1@example.com");
        User createdUser = client.createUser(newUserParams);
*/

/*
    	Map<String, Object> newMapParams = new HashMap<String, Object>();
    	newMapParams.put("name", "My Fiest Mapping");
    	newMapParams.put("match", "all");
    	newMapParams.put("enabled", true);
        Mapping createdMapping = client.createMapping(newMapParams);
*/

        int i=0;
    }
}
