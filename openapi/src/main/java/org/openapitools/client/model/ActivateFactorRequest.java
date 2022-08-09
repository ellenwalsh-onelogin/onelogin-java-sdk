/*
 * OneLogin API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 0.0.1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package org.openapitools.client.model;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
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
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.openapitools.client.JSON;

/**
 * ActivateFactorRequest
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2022-08-09T11:03:49.744981-07:00[America/Los_Angeles]")
public class ActivateFactorRequest {
  public static final String SERIALIZED_NAME_DEVICE_ID = "device_id";
  @SerializedName(SERIALIZED_NAME_DEVICE_ID)
  private Integer deviceId;

  public static final String SERIALIZED_NAME_EXPIRES_IN = "expires_in";
  @SerializedName(SERIALIZED_NAME_EXPIRES_IN)
  private Integer expiresIn;

  public static final String SERIALIZED_NAME_REDIRECT_TO = "redirect_to";
  @SerializedName(SERIALIZED_NAME_REDIRECT_TO)
  private String redirectTo;

  public static final String SERIALIZED_NAME_CUSTOM_MESSAGE = "custom_message";
  @SerializedName(SERIALIZED_NAME_CUSTOM_MESSAGE)
  private String customMessage;

  public ActivateFactorRequest() { 
  }

  public ActivateFactorRequest deviceId(Integer deviceId) {
    
    this.deviceId = deviceId;
    return this;
  }

   /**
   * Required. Specifies the factor to be verified.
   * @return deviceId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Required. Specifies the factor to be verified.")

  public Integer getDeviceId() {
    return deviceId;
  }


  public void setDeviceId(Integer deviceId) {
    this.deviceId = deviceId;
  }


  public ActivateFactorRequest expiresIn(Integer expiresIn) {
    
    this.expiresIn = expiresIn;
    return this;
  }

   /**
   * Optional. Sets the window of time in seconds that the factor must be verified within. 
   * @return expiresIn
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Optional. Sets the window of time in seconds that the factor must be verified within. ")

  public Integer getExpiresIn() {
    return expiresIn;
  }


  public void setExpiresIn(Integer expiresIn) {
    this.expiresIn = expiresIn;
  }


  public ActivateFactorRequest redirectTo(String redirectTo) {
    
    this.redirectTo = redirectTo;
    return this;
  }

   /**
   * Optional. Only applies to Email MagicLink factor.
   * @return redirectTo
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Optional. Only applies to Email MagicLink factor.")

  public String getRedirectTo() {
    return redirectTo;
  }


  public void setRedirectTo(String redirectTo) {
    this.redirectTo = redirectTo;
  }


  public ActivateFactorRequest customMessage(String customMessage) {
    
    this.customMessage = customMessage;
    return this;
  }

   /**
   * Optional. Only applies to SMS factor. A message template that will be sent via SMS.
   * @return customMessage
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Optional. Only applies to SMS factor. A message template that will be sent via SMS.")

  public String getCustomMessage() {
    return customMessage;
  }


  public void setCustomMessage(String customMessage) {
    this.customMessage = customMessage;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ActivateFactorRequest activateFactorRequest = (ActivateFactorRequest) o;
    return Objects.equals(this.deviceId, activateFactorRequest.deviceId) &&
        Objects.equals(this.expiresIn, activateFactorRequest.expiresIn) &&
        Objects.equals(this.redirectTo, activateFactorRequest.redirectTo) &&
        Objects.equals(this.customMessage, activateFactorRequest.customMessage);
  }

  @Override
  public int hashCode() {
    return Objects.hash(deviceId, expiresIn, redirectTo, customMessage);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ActivateFactorRequest {\n");
    sb.append("    deviceId: ").append(toIndentedString(deviceId)).append("\n");
    sb.append("    expiresIn: ").append(toIndentedString(expiresIn)).append("\n");
    sb.append("    redirectTo: ").append(toIndentedString(redirectTo)).append("\n");
    sb.append("    customMessage: ").append(toIndentedString(customMessage)).append("\n");
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
    openapiFields.add("device_id");
    openapiFields.add("expires_in");
    openapiFields.add("redirect_to");
    openapiFields.add("custom_message");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to ActivateFactorRequest
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (ActivateFactorRequest.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in ActivateFactorRequest is not found in the empty JSON string", ActivateFactorRequest.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!ActivateFactorRequest.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `ActivateFactorRequest` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      if (jsonObj.get("redirect_to") != null && !jsonObj.get("redirect_to").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `redirect_to` to be a primitive type in the JSON string but got `%s`", jsonObj.get("redirect_to").toString()));
      }
      if (jsonObj.get("custom_message") != null && !jsonObj.get("custom_message").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `custom_message` to be a primitive type in the JSON string but got `%s`", jsonObj.get("custom_message").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!ActivateFactorRequest.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'ActivateFactorRequest' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<ActivateFactorRequest> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(ActivateFactorRequest.class));

       return (TypeAdapter<T>) new TypeAdapter<ActivateFactorRequest>() {
           @Override
           public void write(JsonWriter out, ActivateFactorRequest value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public ActivateFactorRequest read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of ActivateFactorRequest given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of ActivateFactorRequest
  * @throws IOException if the JSON string is invalid with respect to ActivateFactorRequest
  */
  public static ActivateFactorRequest fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, ActivateFactorRequest.class);
  }

 /**
  * Convert an instance of ActivateFactorRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

