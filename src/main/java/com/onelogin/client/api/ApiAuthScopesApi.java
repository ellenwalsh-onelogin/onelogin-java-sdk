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

import com.onelogin.client.ApiCallback;
import com.onelogin.client.ApiClient;
import com.onelogin.client.ApiException;
import com.onelogin.client.ApiResponse;
import com.onelogin.client.Configuration;
import com.onelogin.client.Pair;
import com.onelogin.client.ProgressRequestBody;
import com.onelogin.client.ProgressResponseBody;

import com.google.gson.reflect.TypeToken;

import java.io.IOException;


import com.onelogin.client.model.AltErr;
import com.onelogin.client.model.AuthId;
import com.onelogin.client.model.AuthScope;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.ws.rs.core.GenericType;

public class ApiAuthScopesApi {
    private ApiClient localVarApiClient;
    private int localHostIndex;
    private String localCustomBaseUrl;

    public ApiAuthScopesApi() {
        this(Configuration.getDefaultApiClient());
    }

    public ApiAuthScopesApi(ApiClient apiClient) {
        this.localVarApiClient = apiClient;
    }

    public ApiClient getApiClient() {
        return localVarApiClient;
    }

    public void setApiClient(ApiClient apiClient) {
        this.localVarApiClient = apiClient;
    }

    public int getHostIndex() {
        return localHostIndex;
    }

    public void setHostIndex(int hostIndex) {
        this.localHostIndex = hostIndex;
    }

    public String getCustomBaseUrl() {
        return localCustomBaseUrl;
    }

    public void setCustomBaseUrl(String customBaseUrl) {
        this.localCustomBaseUrl = customBaseUrl;
    }

    /**
     * Build call for createScope
     * @param apiAuthId  (required)
     * @param contentType  (optional, default to application/json)
     * @param authScope  (optional)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
        <tr><td> 422 </td><td> Unprocessable Entity </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call createScopeCall(String apiAuthId, String contentType, AuthScope authScope, final ApiCallback _callback) throws ApiException {
        String basePath = null;
        // Operation Servers
        String[] localBasePaths = new String[] {  };

        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        } else if ( localBasePaths.length > 0 ) {
            basePath = localBasePaths[localHostIndex];
        } else {
            basePath = null;
        }

        Object localVarPostBody = authScope;

        // create path and map variables
        String localVarPath = "/api/2/api_authorizations/{api_auth_id}/scopes"
            .replace("{" + "api_auth_id" + "}", localVarApiClient.escapeString(apiAuthId.toString()));

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        if (contentType != null) {
            localVarHeaderParams.put("Content-Type", localVarApiClient.parameterToString(contentType));
        }

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
            "application/json"
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarContentType != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] { "OAuth2" };
        return localVarApiClient.buildCall(basePath, localVarPath, "POST", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call createScopeValidateBeforeCall(String apiAuthId, String contentType, AuthScope authScope, final ApiCallback _callback) throws ApiException {
        // verify the required parameter 'apiAuthId' is set
        if (apiAuthId == null) {
            throw new ApiException("Missing the required parameter 'apiAuthId' when calling createScope(Async)");
        }

        return createScopeCall(apiAuthId, contentType, authScope, _callback);

    }

    /**
     * Create Api Auth Server Scope
     * Create API Auth Server Scope
     * @param apiAuthId  (required)
     * @param contentType  (optional, default to application/json)
     * @param authScope  (optional)
     * @return AuthScope
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
        <tr><td> 422 </td><td> Unprocessable Entity </td><td>  -  </td></tr>
     </table>
     */
    public AuthScope createScope(String apiAuthId, String contentType, AuthScope authScope) throws ApiException {
        ApiResponse<AuthScope> localVarResp = createScopeWithHttpInfo(apiAuthId, contentType, authScope);
        return localVarResp.getData();
    }

    /**
     * Create Api Auth Server Scope
     * Create API Auth Server Scope
     * @param apiAuthId  (required)
     * @param contentType  (optional, default to application/json)
     * @param authScope  (optional)
     * @return ApiResponse&lt;AuthScope&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
        <tr><td> 422 </td><td> Unprocessable Entity </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<AuthScope> createScopeWithHttpInfo(String apiAuthId, String contentType, AuthScope authScope) throws ApiException {
        okhttp3.Call localVarCall = createScopeValidateBeforeCall(apiAuthId, contentType, authScope, null);
        Type localVarReturnType = new TypeToken<AuthScope>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * Create Api Auth Server Scope (asynchronously)
     * Create API Auth Server Scope
     * @param apiAuthId  (required)
     * @param contentType  (optional, default to application/json)
     * @param authScope  (optional)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
        <tr><td> 422 </td><td> Unprocessable Entity </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call createScopeAsync(String apiAuthId, String contentType, AuthScope authScope, final ApiCallback<AuthScope> _callback) throws ApiException {

        okhttp3.Call localVarCall = createScopeValidateBeforeCall(apiAuthId, contentType, authScope, _callback);
        Type localVarReturnType = new TypeToken<AuthScope>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
    /**
     * Build call for deleteScope
     * @param apiAuthId  (required)
     * @param scopeId  (required)
     * @param contentType  (optional, default to application/json)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 204 </td><td> Success. The scope is deleted. No content is returned. </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call deleteScopeCall(String apiAuthId, Integer scopeId, String contentType, final ApiCallback _callback) throws ApiException {
        String basePath = null;
        // Operation Servers
        String[] localBasePaths = new String[] {  };

        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        } else if ( localBasePaths.length > 0 ) {
            basePath = localBasePaths[localHostIndex];
        } else {
            basePath = null;
        }

        Object localVarPostBody = null;

        // create path and map variables
        String localVarPath = "/api/2/api_authorizations/{api_auth_id}/scopes/{scope_id}"
            .replace("{" + "api_auth_id" + "}", localVarApiClient.escapeString(apiAuthId.toString()))
            .replace("{" + "scope_id" + "}", localVarApiClient.escapeString(scopeId.toString()));

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        if (contentType != null) {
            localVarHeaderParams.put("Content-Type", localVarApiClient.parameterToString(contentType));
        }

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarContentType != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] { "OAuth2" };
        return localVarApiClient.buildCall(basePath, localVarPath, "DELETE", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call deleteScopeValidateBeforeCall(String apiAuthId, Integer scopeId, String contentType, final ApiCallback _callback) throws ApiException {
        // verify the required parameter 'apiAuthId' is set
        if (apiAuthId == null) {
            throw new ApiException("Missing the required parameter 'apiAuthId' when calling deleteScope(Async)");
        }

        // verify the required parameter 'scopeId' is set
        if (scopeId == null) {
            throw new ApiException("Missing the required parameter 'scopeId' when calling deleteScope(Async)");
        }

        return deleteScopeCall(apiAuthId, scopeId, contentType, _callback);

    }

    /**
     * Delete Api Auth Server Scope
     * Delete Scope
     * @param apiAuthId  (required)
     * @param scopeId  (required)
     * @param contentType  (optional, default to application/json)
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 204 </td><td> Success. The scope is deleted. No content is returned. </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
     </table>
     */
    public void deleteScope(String apiAuthId, Integer scopeId, String contentType) throws ApiException {
        deleteScopeWithHttpInfo(apiAuthId, scopeId, contentType);
    }

    /**
     * Delete Api Auth Server Scope
     * Delete Scope
     * @param apiAuthId  (required)
     * @param scopeId  (required)
     * @param contentType  (optional, default to application/json)
     * @return ApiResponse&lt;Void&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 204 </td><td> Success. The scope is deleted. No content is returned. </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<Void> deleteScopeWithHttpInfo(String apiAuthId, Integer scopeId, String contentType) throws ApiException {
        okhttp3.Call localVarCall = deleteScopeValidateBeforeCall(apiAuthId, scopeId, contentType, null);
        return localVarApiClient.execute(localVarCall);
    }

    /**
     * Delete Api Auth Server Scope (asynchronously)
     * Delete Scope
     * @param apiAuthId  (required)
     * @param scopeId  (required)
     * @param contentType  (optional, default to application/json)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 204 </td><td> Success. The scope is deleted. No content is returned. </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call deleteScopeAsync(String apiAuthId, Integer scopeId, String contentType, final ApiCallback<Void> _callback) throws ApiException {

        okhttp3.Call localVarCall = deleteScopeValidateBeforeCall(apiAuthId, scopeId, contentType, _callback);
        localVarApiClient.executeAsync(localVarCall, _callback);
        return localVarCall;
    }
    /**
     * Build call for getScopes
     * @param apiAuthId  (required)
     * @param contentType  (optional, default to application/json)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call getScopesCall(String apiAuthId, String contentType, final ApiCallback _callback) throws ApiException {
        String basePath = null;
        // Operation Servers
        String[] localBasePaths = new String[] {  };

        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        } else if ( localBasePaths.length > 0 ) {
            basePath = localBasePaths[localHostIndex];
        } else {
            basePath = null;
        }

        Object localVarPostBody = null;

        // create path and map variables
        String localVarPath = "/api/2/api_authorizations/{api_auth_id}/scopes"
            .replace("{" + "api_auth_id" + "}", localVarApiClient.escapeString(apiAuthId.toString()));

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        if (contentType != null) {
            localVarHeaderParams.put("Content-Type", localVarApiClient.parameterToString(contentType));
        }

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarContentType != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] { "OAuth2" };
        return localVarApiClient.buildCall(basePath, localVarPath, "GET", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call getScopesValidateBeforeCall(String apiAuthId, String contentType, final ApiCallback _callback) throws ApiException {
        // verify the required parameter 'apiAuthId' is set
        if (apiAuthId == null) {
            throw new ApiException("Missing the required parameter 'apiAuthId' when calling getScopes(Async)");
        }

        return getScopesCall(apiAuthId, contentType, _callback);

    }

    /**
     * Get Api Auth Server Scopes
     * List Authorization Scopes
     * @param apiAuthId  (required)
     * @param contentType  (optional, default to application/json)
     * @return List&lt;AuthScope&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
     </table>
     */
    public List<AuthScope> getScopes(String apiAuthId, String contentType) throws ApiException {
        ApiResponse<List<AuthScope>> localVarResp = getScopesWithHttpInfo(apiAuthId, contentType);
        return localVarResp.getData();
    }

    /**
     * Get Api Auth Server Scopes
     * List Authorization Scopes
     * @param apiAuthId  (required)
     * @param contentType  (optional, default to application/json)
     * @return ApiResponse&lt;List&lt;AuthScope&gt;&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<List<AuthScope>> getScopesWithHttpInfo(String apiAuthId, String contentType) throws ApiException {
        okhttp3.Call localVarCall = getScopesValidateBeforeCall(apiAuthId, contentType, null);
        Type localVarReturnType = new TypeToken<List<AuthScope>>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * Get Api Auth Server Scopes (asynchronously)
     * List Authorization Scopes
     * @param apiAuthId  (required)
     * @param contentType  (optional, default to application/json)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call getScopesAsync(String apiAuthId, String contentType, final ApiCallback<List<AuthScope>> _callback) throws ApiException {

        okhttp3.Call localVarCall = getScopesValidateBeforeCall(apiAuthId, contentType, _callback);
        Type localVarReturnType = new TypeToken<List<AuthScope>>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
    /**
     * Build call for updateScope
     * @param apiAuthId  (required)
     * @param scopeId  (required)
     * @param contentType  (optional, default to application/json)
     * @param authScope  (optional)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
        <tr><td> 422 </td><td> Unprocessable Entity </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call updateScopeCall(String apiAuthId, Integer scopeId, String contentType, AuthScope authScope, final ApiCallback _callback) throws ApiException {
        String basePath = null;
        // Operation Servers
        String[] localBasePaths = new String[] {  };

        // Determine Base Path to Use
        if (localCustomBaseUrl != null){
            basePath = localCustomBaseUrl;
        } else if ( localBasePaths.length > 0 ) {
            basePath = localBasePaths[localHostIndex];
        } else {
            basePath = null;
        }

        Object localVarPostBody = authScope;

        // create path and map variables
        String localVarPath = "/api/2/api_authorizations/{api_auth_id}/scopes/{scope_id}"
            .replace("{" + "api_auth_id" + "}", localVarApiClient.escapeString(apiAuthId.toString()))
            .replace("{" + "scope_id" + "}", localVarApiClient.escapeString(scopeId.toString()));

        List<Pair> localVarQueryParams = new ArrayList<Pair>();
        List<Pair> localVarCollectionQueryParams = new ArrayList<Pair>();
        Map<String, String> localVarHeaderParams = new HashMap<String, String>();
        Map<String, String> localVarCookieParams = new HashMap<String, String>();
        Map<String, Object> localVarFormParams = new HashMap<String, Object>();

        if (contentType != null) {
            localVarHeaderParams.put("Content-Type", localVarApiClient.parameterToString(contentType));
        }

        final String[] localVarAccepts = {
            "application/json"
        };
        final String localVarAccept = localVarApiClient.selectHeaderAccept(localVarAccepts);
        if (localVarAccept != null) {
            localVarHeaderParams.put("Accept", localVarAccept);
        }

        final String[] localVarContentTypes = {
            "application/json"
        };
        final String localVarContentType = localVarApiClient.selectHeaderContentType(localVarContentTypes);
        if (localVarContentType != null) {
            localVarHeaderParams.put("Content-Type", localVarContentType);
        }

        String[] localVarAuthNames = new String[] { "OAuth2" };
        return localVarApiClient.buildCall(basePath, localVarPath, "PUT", localVarQueryParams, localVarCollectionQueryParams, localVarPostBody, localVarHeaderParams, localVarCookieParams, localVarFormParams, localVarAuthNames, _callback);
    }

    @SuppressWarnings("rawtypes")
    private okhttp3.Call updateScopeValidateBeforeCall(String apiAuthId, Integer scopeId, String contentType, AuthScope authScope, final ApiCallback _callback) throws ApiException {
        // verify the required parameter 'apiAuthId' is set
        if (apiAuthId == null) {
            throw new ApiException("Missing the required parameter 'apiAuthId' when calling updateScope(Async)");
        }

        // verify the required parameter 'scopeId' is set
        if (scopeId == null) {
            throw new ApiException("Missing the required parameter 'scopeId' when calling updateScope(Async)");
        }

        return updateScopeCall(apiAuthId, scopeId, contentType, authScope, _callback);

    }

    /**
     * Update Api Auth Server Scope
     * Update Scope
     * @param apiAuthId  (required)
     * @param scopeId  (required)
     * @param contentType  (optional, default to application/json)
     * @param authScope  (optional)
     * @return AuthId
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
        <tr><td> 422 </td><td> Unprocessable Entity </td><td>  -  </td></tr>
     </table>
     */
    public AuthId updateScope(String apiAuthId, Integer scopeId, String contentType, AuthScope authScope) throws ApiException {
        ApiResponse<AuthId> localVarResp = updateScopeWithHttpInfo(apiAuthId, scopeId, contentType, authScope);
        return localVarResp.getData();
    }

    /**
     * Update Api Auth Server Scope
     * Update Scope
     * @param apiAuthId  (required)
     * @param scopeId  (required)
     * @param contentType  (optional, default to application/json)
     * @param authScope  (optional)
     * @return ApiResponse&lt;AuthId&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
        <tr><td> 422 </td><td> Unprocessable Entity </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<AuthId> updateScopeWithHttpInfo(String apiAuthId, Integer scopeId, String contentType, AuthScope authScope) throws ApiException {
        okhttp3.Call localVarCall = updateScopeValidateBeforeCall(apiAuthId, scopeId, contentType, authScope, null);
        Type localVarReturnType = new TypeToken<AuthId>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * Update Api Auth Server Scope (asynchronously)
     * Update Scope
     * @param apiAuthId  (required)
     * @param scopeId  (required)
     * @param contentType  (optional, default to application/json)
     * @param authScope  (optional)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
        <tr><td> 422 </td><td> Unprocessable Entity </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call updateScopeAsync(String apiAuthId, Integer scopeId, String contentType, AuthScope authScope, final ApiCallback<AuthId> _callback) throws ApiException {

        okhttp3.Call localVarCall = updateScopeValidateBeforeCall(apiAuthId, scopeId, contentType, authScope, _callback);
        Type localVarReturnType = new TypeToken<AuthId>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
}