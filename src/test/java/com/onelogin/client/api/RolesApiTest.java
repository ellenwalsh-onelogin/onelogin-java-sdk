/*
 * OneLogin API
 * OpenAPI Specification for OneLogin
 *
 * The version of the OpenAPI document: 3.1.1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.onelogin.client.api;

import com.onelogin.client.ApiException;
import com.onelogin.client.model.AltErr;
import com.onelogin.client.model.CreateRole201ResponseInner;
import com.onelogin.client.model.Error;
import com.onelogin.client.model.GetRoleApps200ResponseInner;
import com.onelogin.client.model.GetRoleById200Response;
import com.onelogin.client.model.GetRoleByName200Response;
import com.onelogin.client.model.RemoveRoleUsersRequest;
import com.onelogin.client.model.Role;
import com.onelogin.client.model.UpdateRole200Response;
import com.onelogin.client.model.User;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * API tests for RolesApi
 */
@Disabled
public class RolesApiTest {

    private final RolesApi api = new RolesApi();

    /**
     * Add Role Admins
     *
     * Add Role Admins
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void addRoleAdminsTest() throws ApiException {
        String roleId = null;
        List<Integer> requestBody = null;
        List<CreateRole201ResponseInner> response = api.addRoleAdmins(roleId, requestBody);
        // TODO: test validations
    }

    /**
     * Add Role Users
     *
     * Add Role Users
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void addRoleUsersTest() throws ApiException {
        String roleId = null;
        List<Integer> requestBody = null;
        List<CreateRole201ResponseInner> response = api.addRoleUsers(roleId, requestBody);
        // TODO: test validations
    }

    /**
     * Create Role
     *
     * Create Role
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void createRoleTest() throws ApiException {
        Role role = null;
        List<CreateRole201ResponseInner> response = api.createRole(role);
        // TODO: test validations
    }

    /**
     * Delete Role by ID
     *
     * Delete Role
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void deleteRoleTest() throws ApiException {
        String roleId = null;
        api.deleteRole(roleId);
        // TODO: test validations
    }

    /**
     * Get Role by ID
     *
     * Get Role
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void getRoleTest() throws ApiException {
        String roleId = null;
        Role response = api.getRole(roleId);
        // TODO: test validations
    }

    /**
     * Get Role Admins
     *
     * Get Role Admins
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void getRoleAdminsTest() throws ApiException {
        String roleId = null;
        Integer limit = null;
        Integer page = null;
        String cursor = null;
        String name = null;
        Boolean includeUnassigned = null;
        List<User> response = api.getRoleAdmins(roleId, limit, page, cursor, name, includeUnassigned);
        // TODO: test validations
    }

    /**
     * Get all Apps assigned to Role
     *
     * Get Role Apps
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void getRoleAppsTest() throws ApiException {
        String roleId = null;
        Integer limit = null;
        Integer page = null;
        String cursor = null;
        Boolean assigned = null;
        List<GetRoleApps200ResponseInner> response = api.getRoleApps(roleId, limit, page, cursor, assigned);
        // TODO: test validations
    }

    /**
     * Get Role by ID
     *
     * Get Role By ID
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void getRoleByIdTest() throws ApiException {
        String roleId = null;
        GetRoleById200Response response = api.getRoleById(roleId);
        // TODO: test validations
    }

    /**
     * Get Role by Name
     *
     * Get Role by Name
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void getRoleByNameTest() throws ApiException {
        String name = null;
        GetRoleByName200Response response = api.getRoleByName(name);
        // TODO: test validations
    }

    /**
     * Get Role Users
     *
     * Get Role Users
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void getRoleUsersTest() throws ApiException {
        String roleId = null;
        Integer limit = null;
        Integer page = null;
        String cursor = null;
        String name = null;
        Boolean includeUnassigned = null;
        List<User> response = api.getRoleUsers(roleId, limit, page, cursor, name, includeUnassigned);
        // TODO: test validations
    }

    /**
     * List Roles
     *
     * List Roles
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void listRolesTest() throws ApiException {
        Integer appId = null;
        Integer limit = null;
        Integer page = null;
        String cursor = null;
        String roleName = null;
        String appName = null;
        String fields = null;
        List<Role> response = api.listRoles(appId, limit, page, cursor, roleName, appName, fields);
        // TODO: test validations
    }

    /**
     * Remove Role Admins
     *
     * Remove Role Admins
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void removeRoleAdminsTest() throws ApiException {
        String roleId = null;
        RemoveRoleUsersRequest removeRoleUsersRequest = null;
        api.removeRoleAdmins(roleId, removeRoleUsersRequest);
        // TODO: test validations
    }

    /**
     * Remove Role Users
     *
     * Remove Role Users
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void removeRoleUsersTest() throws ApiException {
        String roleId = null;
        RemoveRoleUsersRequest removeRoleUsersRequest = null;
        api.removeRoleUsers(roleId, removeRoleUsersRequest);
        // TODO: test validations
    }

    /**
     * Set Role Apps
     *
     * Set Role Apps
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void setRoleAppsTest() throws ApiException {
        String roleId = null;
        List<Integer> requestBody = null;
        List<CreateRole201ResponseInner> response = api.setRoleApps(roleId, requestBody);
        // TODO: test validations
    }

    /**
     * Update Role
     *
     * Update Role
     *
     * @throws ApiException if the Api call fails
     */
    @Test
    public void updateRoleTest() throws ApiException {
        String roleId = null;
        Role role = null;
        UpdateRole200Response response = api.updateRole(roleId, role);
        // TODO: test validations
    }

}
