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


import com.onelogin.client.model.Error;
import com.onelogin.client.model.GenerateSamlAssert200Response;
import com.onelogin.client.model.SamlAssert;
import com.onelogin.client.model.SamlFactor;
import com.onelogin.client.model.VerFactorSaml200Response;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.ws.rs.core.GenericType;

public class SamlAssertionsApi {
    private ApiClient localVarApiClient;
    private int localHostIndex;
    private String localCustomBaseUrl;

    public SamlAssertionsApi() {
        this(Configuration.getDefaultApiClient());
    }

    public SamlAssertionsApi(ApiClient apiClient) {
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
     * Build call for generateSamlAssert
     * @param contentType  (optional, default to application/json)
     * @param samlAssert  (optional)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call generateSamlAssertCall(String contentType, SamlAssert samlAssert, final ApiCallback _callback) throws ApiException {
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

        Object localVarPostBody = samlAssert;

        // create path and map variables
        String localVarPath = "/api/1/saml_assertion";

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
    private okhttp3.Call generateSamlAssertValidateBeforeCall(String contentType, SamlAssert samlAssert, final ApiCallback _callback) throws ApiException {
        return generateSamlAssertCall(contentType, samlAssert, _callback);

    }

    /**
     * Generate SAML Assertion
     * Generate SAML Assertion
     * @param contentType  (optional, default to application/json)
     * @param samlAssert  (optional)
     * @return GenerateSamlAssert200Response
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
     </table>
     */
    public GenerateSamlAssert200Response generateSamlAssert(String contentType, SamlAssert samlAssert) throws ApiException {
        ApiResponse<GenerateSamlAssert200Response> localVarResp = generateSamlAssertWithHttpInfo(contentType, samlAssert);
        return localVarResp.getData();
    }

    /**
     * Generate SAML Assertion
     * Generate SAML Assertion
     * @param contentType  (optional, default to application/json)
     * @param samlAssert  (optional)
     * @return ApiResponse&lt;GenerateSamlAssert200Response&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<GenerateSamlAssert200Response> generateSamlAssertWithHttpInfo(String contentType, SamlAssert samlAssert) throws ApiException {
        okhttp3.Call localVarCall = generateSamlAssertValidateBeforeCall(contentType, samlAssert, null);
        Type localVarReturnType = new TypeToken<GenerateSamlAssert200Response>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * Generate SAML Assertion (asynchronously)
     * Generate SAML Assertion
     * @param contentType  (optional, default to application/json)
     * @param samlAssert  (optional)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call generateSamlAssertAsync(String contentType, SamlAssert samlAssert, final ApiCallback<GenerateSamlAssert200Response> _callback) throws ApiException {

        okhttp3.Call localVarCall = generateSamlAssertValidateBeforeCall(contentType, samlAssert, _callback);
        Type localVarReturnType = new TypeToken<GenerateSamlAssert200Response>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
    /**
     * Build call for generateSamlAssert2
     * @param contentType  (optional, default to application/json)
     * @param samlAssert  (optional)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call generateSamlAssert2Call(String contentType, SamlAssert samlAssert, final ApiCallback _callback) throws ApiException {
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

        Object localVarPostBody = samlAssert;

        // create path and map variables
        String localVarPath = "/api/2/saml_assertion";

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
    private okhttp3.Call generateSamlAssert2ValidateBeforeCall(String contentType, SamlAssert samlAssert, final ApiCallback _callback) throws ApiException {
        return generateSamlAssert2Call(contentType, samlAssert, _callback);

    }

    /**
     * Generate SAML Assertion
     * Generate SAML Assertion
     * @param contentType  (optional, default to application/json)
     * @param samlAssert  (optional)
     * @return GenerateSamlAssert200Response
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
     </table>
     */
    public GenerateSamlAssert200Response generateSamlAssert2(String contentType, SamlAssert samlAssert) throws ApiException {
        ApiResponse<GenerateSamlAssert200Response> localVarResp = generateSamlAssert2WithHttpInfo(contentType, samlAssert);
        return localVarResp.getData();
    }

    /**
     * Generate SAML Assertion
     * Generate SAML Assertion
     * @param contentType  (optional, default to application/json)
     * @param samlAssert  (optional)
     * @return ApiResponse&lt;GenerateSamlAssert200Response&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<GenerateSamlAssert200Response> generateSamlAssert2WithHttpInfo(String contentType, SamlAssert samlAssert) throws ApiException {
        okhttp3.Call localVarCall = generateSamlAssert2ValidateBeforeCall(contentType, samlAssert, null);
        Type localVarReturnType = new TypeToken<GenerateSamlAssert200Response>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * Generate SAML Assertion (asynchronously)
     * Generate SAML Assertion
     * @param contentType  (optional, default to application/json)
     * @param samlAssert  (optional)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call generateSamlAssert2Async(String contentType, SamlAssert samlAssert, final ApiCallback<GenerateSamlAssert200Response> _callback) throws ApiException {

        okhttp3.Call localVarCall = generateSamlAssert2ValidateBeforeCall(contentType, samlAssert, _callback);
        Type localVarReturnType = new TypeToken<GenerateSamlAssert200Response>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
    /**
     * Build call for verFactorSaml
     * @param contentType  (optional, default to application/json)
     * @param samlFactor  (optional)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call verFactorSamlCall(String contentType, SamlFactor samlFactor, final ApiCallback _callback) throws ApiException {
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

        Object localVarPostBody = samlFactor;

        // create path and map variables
        String localVarPath = "/api/1/saml_assertion/verify_factor";

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
    private okhttp3.Call verFactorSamlValidateBeforeCall(String contentType, SamlFactor samlFactor, final ApiCallback _callback) throws ApiException {
        return verFactorSamlCall(contentType, samlFactor, _callback);

    }

    /**
     * Verify Factor SAML
     * Verify Factor: SAML
     * @param contentType  (optional, default to application/json)
     * @param samlFactor  (optional)
     * @return VerFactorSaml200Response
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
     </table>
     */
    public VerFactorSaml200Response verFactorSaml(String contentType, SamlFactor samlFactor) throws ApiException {
        ApiResponse<VerFactorSaml200Response> localVarResp = verFactorSamlWithHttpInfo(contentType, samlFactor);
        return localVarResp.getData();
    }

    /**
     * Verify Factor SAML
     * Verify Factor: SAML
     * @param contentType  (optional, default to application/json)
     * @param samlFactor  (optional)
     * @return ApiResponse&lt;VerFactorSaml200Response&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<VerFactorSaml200Response> verFactorSamlWithHttpInfo(String contentType, SamlFactor samlFactor) throws ApiException {
        okhttp3.Call localVarCall = verFactorSamlValidateBeforeCall(contentType, samlFactor, null);
        Type localVarReturnType = new TypeToken<VerFactorSaml200Response>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * Verify Factor SAML (asynchronously)
     * Verify Factor: SAML
     * @param contentType  (optional, default to application/json)
     * @param samlFactor  (optional)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call verFactorSamlAsync(String contentType, SamlFactor samlFactor, final ApiCallback<VerFactorSaml200Response> _callback) throws ApiException {

        okhttp3.Call localVarCall = verFactorSamlValidateBeforeCall(contentType, samlFactor, _callback);
        Type localVarReturnType = new TypeToken<VerFactorSaml200Response>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
    /**
     * Build call for verFactorSaml2
     * @param contentType  (optional, default to application/json)
     * @param samlFactor  (optional)
     * @param _callback Callback for upload/download progress
     * @return Call to execute
     * @throws ApiException If fail to serialize the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call verFactorSaml2Call(String contentType, SamlFactor samlFactor, final ApiCallback _callback) throws ApiException {
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

        Object localVarPostBody = samlFactor;

        // create path and map variables
        String localVarPath = "/api/2/saml_assertion/verify_factor";

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
    private okhttp3.Call verFactorSaml2ValidateBeforeCall(String contentType, SamlFactor samlFactor, final ApiCallback _callback) throws ApiException {
        return verFactorSaml2Call(contentType, samlFactor, _callback);

    }

    /**
     * Verify Factor SAML
     * Verify Factor: SAML
     * @param contentType  (optional, default to application/json)
     * @param samlFactor  (optional)
     * @return VerFactorSaml200Response
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
     </table>
     */
    public VerFactorSaml200Response verFactorSaml2(String contentType, SamlFactor samlFactor) throws ApiException {
        ApiResponse<VerFactorSaml200Response> localVarResp = verFactorSaml2WithHttpInfo(contentType, samlFactor);
        return localVarResp.getData();
    }

    /**
     * Verify Factor SAML
     * Verify Factor: SAML
     * @param contentType  (optional, default to application/json)
     * @param samlFactor  (optional)
     * @return ApiResponse&lt;VerFactorSaml200Response&gt;
     * @throws ApiException If fail to call the API, e.g. server error or cannot deserialize the response body
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
     </table>
     */
    public ApiResponse<VerFactorSaml200Response> verFactorSaml2WithHttpInfo(String contentType, SamlFactor samlFactor) throws ApiException {
        okhttp3.Call localVarCall = verFactorSaml2ValidateBeforeCall(contentType, samlFactor, null);
        Type localVarReturnType = new TypeToken<VerFactorSaml200Response>(){}.getType();
        return localVarApiClient.execute(localVarCall, localVarReturnType);
    }

    /**
     * Verify Factor SAML (asynchronously)
     * Verify Factor: SAML
     * @param contentType  (optional, default to application/json)
     * @param samlFactor  (optional)
     * @param _callback The callback to be executed when the API call finishes
     * @return The request call
     * @throws ApiException If fail to process the API call, e.g. serializing the request body object
     * @http.response.details
     <table summary="Response Details" border="1">
        <tr><td> Status Code </td><td> Description </td><td> Response Headers </td></tr>
        <tr><td> 200 </td><td> Successful response </td><td>  -  </td></tr>
        <tr><td> 400 </td><td> Bad Request </td><td>  -  </td></tr>
        <tr><td> 401 </td><td> Unauthorized </td><td>  -  </td></tr>
        <tr><td> 404 </td><td> Not Found </td><td>  -  </td></tr>
     </table>
     */
    public okhttp3.Call verFactorSaml2Async(String contentType, SamlFactor samlFactor, final ApiCallback<VerFactorSaml200Response> _callback) throws ApiException {

        okhttp3.Call localVarCall = verFactorSaml2ValidateBeforeCall(contentType, samlFactor, _callback);
        Type localVarReturnType = new TypeToken<VerFactorSaml200Response>(){}.getType();
        localVarApiClient.executeAsync(localVarCall, localVarReturnType, _callback);
        return localVarCall;
    }
}
