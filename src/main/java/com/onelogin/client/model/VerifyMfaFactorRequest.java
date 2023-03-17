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


package com.onelogin.client.model;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.onelogin.client.JSON;

/**
 * VerifyMfaFactorRequest
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2023-03-16T13:09:58.336938-07:00[America/Los_Angeles]")
public class VerifyMfaFactorRequest {
  public static final String SERIALIZED_NAME_STATE_TOKEN = "state_token";
  @SerializedName(SERIALIZED_NAME_STATE_TOKEN)
  private String stateToken;

  public static final String SERIALIZED_NAME_OTP_TOKEN = "otp_token";
  @SerializedName(SERIALIZED_NAME_OTP_TOKEN)
  private String otpToken;

  public VerifyMfaFactorRequest() {
  }

  public VerifyMfaFactorRequest stateToken(String stateToken) {
    
    this.stateToken = stateToken;
    return this;
  }

   /**
   * The state_token is returned after a successful request to Enroll a Factor or Activate a Factor. The state_token MUST be provided if the needs_trigger attribute from the proceeding calls is set to true. Note that the state_token expires 120 seconds after creation. If the token is expired you will need to Activate the Factor again.
   * @return stateToken
  **/
  @javax.annotation.Nullable

  public String getStateToken() {
    return stateToken;
  }


  public void setStateToken(String stateToken) {
    this.stateToken = stateToken;
  }


  public VerifyMfaFactorRequest otpToken(String otpToken) {
    
    this.otpToken = otpToken;
    return this;
  }

   /**
   * OTP code provided by the device or SMS message sent to user. When a device like OneLogin Protect that supports Push has been used you do not need to provide the otp_token and can keep polling this endpoint until the state_token expires.
   * @return otpToken
  **/
  @javax.annotation.Nullable

  public String getOtpToken() {
    return otpToken;
  }


  public void setOtpToken(String otpToken) {
    this.otpToken = otpToken;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    VerifyMfaFactorRequest verifyMfaFactorRequest = (VerifyMfaFactorRequest) o;
    return Objects.equals(this.stateToken, verifyMfaFactorRequest.stateToken) &&
        Objects.equals(this.otpToken, verifyMfaFactorRequest.otpToken);
  }

  @Override
  public int hashCode() {
    return Objects.hash(stateToken, otpToken);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class VerifyMfaFactorRequest {\n");
    sb.append("    stateToken: ").append(toIndentedString(stateToken)).append("\n");
    sb.append("    otpToken: ").append(toIndentedString(otpToken)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }


  public static HashSet<String> openapiFields;
  public static HashSet<String> openapiRequiredFields;

  static {
    // a set of all properties/fields (JSON key names)
    openapiFields = new HashSet<String>();
    openapiFields.add("state_token");
    openapiFields.add("otp_token");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to VerifyMfaFactorRequest
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (!VerifyMfaFactorRequest.openapiRequiredFields.isEmpty()) { // has required fields but JSON object is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in VerifyMfaFactorRequest is not found in the empty JSON string", VerifyMfaFactorRequest.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!VerifyMfaFactorRequest.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `VerifyMfaFactorRequest` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      if ((jsonObj.get("state_token") != null && !jsonObj.get("state_token").isJsonNull()) && !jsonObj.get("state_token").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `state_token` to be a primitive type in the JSON string but got `%s`", jsonObj.get("state_token").toString()));
      }
      if ((jsonObj.get("otp_token") != null && !jsonObj.get("otp_token").isJsonNull()) && !jsonObj.get("otp_token").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `otp_token` to be a primitive type in the JSON string but got `%s`", jsonObj.get("otp_token").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!VerifyMfaFactorRequest.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'VerifyMfaFactorRequest' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<VerifyMfaFactorRequest> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(VerifyMfaFactorRequest.class));

       return (TypeAdapter<T>) new TypeAdapter<VerifyMfaFactorRequest>() {
           @Override
           public void write(JsonWriter out, VerifyMfaFactorRequest value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public VerifyMfaFactorRequest read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of VerifyMfaFactorRequest given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of VerifyMfaFactorRequest
  * @throws IOException if the JSON string is invalid with respect to VerifyMfaFactorRequest
  */
  public static VerifyMfaFactorRequest fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, VerifyMfaFactorRequest.class);
  }

 /**
  * Convert an instance of VerifyMfaFactorRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

