package com.onelogin.sdk.util;


/**
 * Constants class of OneLogin's Java SDK.
 *
 * A class that contains several constants related to the SDK
 */ 
public final class Constants {

	// Oauth2 URLs
	public static final String TOKEN_REQUEST_URL = "https://api.%s.onelogin.com/auth/oauth2/v2/token";
	public static final String TOKEN_REFRESH_URL = "https://api.%s.onelogin.com/auth/oauth2/v2/token";
	public static final String TOKEN_REVOKE_URL = "https://api.%s.onelogin.com/auth/oauth2/revoke";
	public static final String GET_RATE_URL = "https://api.%s.onelogin.com/auth/rate_limit";

	// User URLs
	public static final String GET_USERS_URL = "https://api.%s.onelogin.com/api/1/users";
	public static final String GET_USER_URL = "https://api.%s.onelogin.com/api/1/users/%s";
	public static final String GET_APPS_FOR_USER_URL = "https://api.%s.onelogin.com/api/1/users/%s/apps";
	public static final String GET_ROLES_FOR_USER_URL = "https://api.%s.onelogin.com/api/1/users/%s/roles";
	public static final String GET_CUSTOM_ATTRIBUTES_URL = "https://api.%s.onelogin.com/api/1/users/custom_attributes";
	public static final String CREATE_USER_URL = "https://api.%s.onelogin.com/api/1/users";
	public static final String SESSION_LOGIN_TOKEN_URL = "https://api.%s.onelogin.com/api/1/login/auth";
	public static final String GET_TOKEN_VERIFY_FACTOR = "https://api.%s.onelogin.com/api/1/login/verify_factor";
	public static final String UPDATE_USER_URL = "https://api.%s.onelogin.com/api/1/users/%s";
	public static final String DELETE_USER_URL = "https://api.%s.onelogin.com/api/1/users/%s";
	public static final String ADD_ROLE_TO_USER_URL = "https://api.%s.onelogin.com/api/1/users/%s/add_roles";
	public static final String DELETE_ROLE_TO_USER_URL = "https://api.%s.onelogin.com/api/1/users/%s/remove_roles";
	public static final String SET_PW_CLEARTEXT = "https://api.%s.onelogin.com/api/1/users/set_password_clear_text/%s";
	public static final String SET_PW_SALT = "https://api.%s.onelogin.com/api/1/users/set_password_using_salt/%s";
	public static final String SET_CUSTOM_ATTRIBUTE_TO_USER_URL = "https://api.%s.onelogin.com/api/1/users/%s/set_custom_attributes";
	public static final String SET_USER_STATE_URL = "https://api.%s.onelogin.com/api/1/users/%s/set_state";
	public static final String LOG_USER_OUT_URL = "https://api.%s.onelogin.com/api/1/users/%s/logout";
	public static final String LOCK_USER_URL = "https://api.%s.onelogin.com/api/1/users/%s/lock_user";
	public static final String GENERATE_MFA_TOKEN_URL = "https://api.%s.onelogin.com/api/1/users/%s/mfa_token";

	// Apps URL
	public static final String GET_APPS_URL = "https://api.%s.onelogin.com/api/1/apps";

	// Role URLs
	public static final String GET_ROLES_URL = "https://api.%s.onelogin.com/api/1/roles";
	public static final String CREATE_ROLE_URL = "https://api.%s.onelogin.com/api/1/roles";
	public static final String GET_ROLE_URL = "https://api.%s.onelogin.com/api/1/roles/%s";

	// Event URLS
	public static final String GET_EVENT_TYPES_URL = "https://api.%s.onelogin.com/api/1/events/types";
	public static final String GET_EVENTS_URL = "https://api.%s.onelogin.com/api/1/events";
	public static final String CREATE_EVENT_URL = "https://api.%s.onelogin.com/api/1/events";
	public static final String GET_EVENT_URL = "https://api.%s.onelogin.com/api/1/events/%s";

	// Group URLs
	public static final String GET_GROUPS_URL = "https://api.%s.onelogin.com/api/1/groups";
	public static final String CREATE_GROUP_URL = "https://api.%s.onelogin.com/api/1/groups";
	public static final String GET_GROUP_URL = "https://api.%s.onelogin.com/api/1/groups/%s";

	// SAML Assertion URLs
	public static final String GET_SAML_ASSERTION_URL = "https://api.%s.onelogin.com/api/1/saml_assertion";
	public static final String GET_SAML_VERIFY_FACTOR = "https://api.%s.onelogin.com/api/1/saml_assertion/verify_factor";

    // Multi-Factor Authentication URLs
	public static final String  GET_FACTORS_URL = "https://api.%s.onelogin.com/api/1/users/%s/auth_factors";
	public static final String  ENROLL_FACTOR_URL = "https://api.%s.onelogin.com/api/1/users/%s/otp_devices";
	public static final String  GET_ENROLLED_FACTORS_URL = "https://api.%s.onelogin.com/api/1/users/%s/otp_devices";
	public static final String  ACTIVATE_FACTOR_URL = "https://api.%s.onelogin.com/api/1/users/%s/otp_devices/%s/trigger";
	public static final String  VERIFY_FACTOR_URL = "https://api.%s.onelogin.com/api/1/users/%s/otp_devices/%s/verify";
	public static final String  REMOVE_FACTOR_URL = "https://api.%s.onelogin.com/api/1/users/%s/otp_devices/%s";
	
	// Invite Link URLS
	public static final String GENERATE_INVITE_LINK_URL = "https://api.%s.onelogin.com/api/1/invites/get_invite_link";
	public static final String SEND_INVITE_LINK_URL = "https://api.%s.onelogin.com/api/1/invites/send_invite_link";

	//Embed Apps URL
	public static final String EMBED_APP_URL = "https://api.onelogin.com/client/apps/embed2";

	// Privilege URLs
	public static final String LIST_PRIVILEGES_URL = "https://api.%s.onelogin.com/api/1/privileges";
	public static final String CREATE_PRIVILEGE_URL = "https://api.%s.onelogin.com/api/1/privileges";
	public static final String UPDATE_PRIVILEGE_URL = "https://api.%s.onelogin.com/api/1/privileges/%s";
	public static final String GET_PRIVILEGE_URL = "https://api.%s.onelogin.com/api/1/privileges/%s";
	public static final String DELETE_PRIVILEGE_URL = "https://api.%s.onelogin.com/api/1/privileges/%s";
	public static final String GET_ROLES_ASSIGNED_TO_PRIVILEGE_URL = "https://api.%s.onelogin.com/api/1/privileges/%s/roles";
	public static final String ASSIGN_ROLES_TO_PRIVILEGE_URL = "https://api.%s.onelogin.com/api/1/privileges/%s/roles";
	public static final String REMOVE_ROLE_FROM_PRIVILEGE_URL = "https://api.%s.onelogin.com/api/1/privileges/%s/roles/%s";
	public static final String GET_USERS_ASSIGNED_TO_PRIVILEGE_URL = "https://api.%s.onelogin.com/api/1/privileges/%s/users";
	public static final String ASSIGN_USERS_TO_PRIVILEGE_URL = "https://api.%s.onelogin.com/api/1/privileges/%s/users";
	public static final String REMOVE_USER_FROM_PRIVILEGE_URL = "https://api.%s.onelogin.com/api/1/privileges/%s/users/%s";
	
	public static final  String[] VALID_ACTIONS = {
	        "apps:List",
	        "apps:Get",
	        "apps:Create",
	        "apps:Update",
	        "apps:Delete",
	        "apps:ManageRoles",
	        "apps:ManageUsers",
	        "directories:List",
	        "directories:Get",
	        "directories:Create",
	        "directories:Update",
	        "directories:Delete",
	        "directories:SyncUsers",
	        "directories:RefreshSchema",
	        "events:List",
	        "events:Get",
	        "mappings:List",
	        "mappings:Get",
	        "mappings:Create",
	        "mappings:Update",
	        "mappings:Delete",
	        "mappings:ReapplyAll",
	        "policies:List",
	        "policies:user:Get",
	        "policies:user:Create",
	        "policies:user:Update",
	        "policies:user:Delete",
	        "policies:app:Get",
	        "policies:app:Create",
	        "policies:app:Update",
	        "policies:app:Delete",
	        "privileges:List",
	        "privileges:Get",
	        "privileges:Create",
	        "privileges:Update",
	        "privileges:Delete",
	        "privileges:ListUsers",
	        "privileges:ListRoles",
	        "privileges:ManageUsers",
	        "privileges:ManageRoles",
	        "reports:List",
	        "reports:Get",
	        "reports:Create",
	        "reports:Update",
	        "reports:Delete",
	        "reports:Run",
	        "roles:List",
	        "roles:Get",
	        "roles:Create",
	        "roles:Update",
	        "roles:Delete",
	        "roles:ManageUsers",
	        "roles:ManageApps",
	        "trustedidp:List",
	        "trustedidp:Get",
	        "trustedidp:Create",
	        "trustedidp:Update",
	        "trustedidp:Delete",
	        "users:List",
	        "users:Get",
	        "users:Create",
	        "users:Update",
	        "users:Delete",
	        "users:Unlock",
	        "users:ResetPassword",
	        "users:ForceLogout",
	        "users:Invite",
	        "users:ReapplyMappings",
	        "users:ManageRoles",
	        "users:ManageApps",
	        "users:GenerateTempMfaToken"
		};
}
