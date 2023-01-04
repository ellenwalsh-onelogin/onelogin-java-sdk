/*
 * OneLogin API
 * OpenAPI Specification for OneLogin
 *
 * The version of the OpenAPI document: 3.1.0
 * Contact: support@onelogin.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.onelogin.sdk.model;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.onelogin.sdk.model.FactorInnerFactorData;
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

import com.onelogin.sdk.JSON;

/**
 * FactorInner
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2023-01-04T13:30:16.594658-08:00[America/Los_Angeles]")
public class FactorInner {
  public static final String SERIALIZED_NAME_ID = "id";
  @SerializedName(SERIALIZED_NAME_ID)
  private String id;

  /**
   * accepted : factor has been verified. pending: registered but has not been verified.
   */
  @JsonAdapter(StatusEnum.Adapter.class)
  public enum StatusEnum {
    PENDING("pending"),
    
    ACCEPTED("accepted");

    private String value;

    StatusEnum(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public static StatusEnum fromValue(String value) {
      for (StatusEnum b : StatusEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }

    public static class Adapter extends TypeAdapter<StatusEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final StatusEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public StatusEnum read(final JsonReader jsonReader) throws IOException {
        String value =  jsonReader.nextString();
        return StatusEnum.fromValue(value);
      }
    }
  }

  public static final String SERIALIZED_NAME_STATUS = "status";
  @SerializedName(SERIALIZED_NAME_STATUS)
  private StatusEnum status;

  public static final String SERIALIZED_NAME_DEFAULT = "default";
  @SerializedName(SERIALIZED_NAME_DEFAULT)
  private Boolean _default;

  public static final String SERIALIZED_NAME_AUTH_FACTOR_NAME = "auth_factor_name";
  @SerializedName(SERIALIZED_NAME_AUTH_FACTOR_NAME)
  private String authFactorName;

  public static final String SERIALIZED_NAME_TYPE_DISPLAY_NAME = "type_display_name";
  @SerializedName(SERIALIZED_NAME_TYPE_DISPLAY_NAME)
  private String typeDisplayName;

  public static final String SERIALIZED_NAME_USER_DISPLAY_NAME = "user_display_name";
  @SerializedName(SERIALIZED_NAME_USER_DISPLAY_NAME)
  private String userDisplayName;

  public static final String SERIALIZED_NAME_EXPIRES_AT = "expires_at";
  @SerializedName(SERIALIZED_NAME_EXPIRES_AT)
  private String expiresAt;

  public static final String SERIALIZED_NAME_FACTOR_DATA = "factor_data";
  @SerializedName(SERIALIZED_NAME_FACTOR_DATA)
  private FactorInnerFactorData factorData;

  public FactorInner() {
  }

  public FactorInner id(String id) {
    
    this.id = id;
    return this;
  }

   /**
   * MFA device identifier.
   * @return id
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "MFA device identifier.")

  public String getId() {
    return id;
  }


  public void setId(String id) {
    this.id = id;
  }


  public FactorInner status(StatusEnum status) {
    
    this.status = status;
    return this;
  }

   /**
   * accepted : factor has been verified. pending: registered but has not been verified.
   * @return status
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "accepted : factor has been verified. pending: registered but has not been verified.")

  public StatusEnum getStatus() {
    return status;
  }


  public void setStatus(StatusEnum status) {
    this.status = status;
  }


  public FactorInner _default(Boolean _default) {
    
    this._default = _default;
    return this;
  }

   /**
   * True &#x3D; is user&#39;s default MFA device for OneLogin.
   * @return _default
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "True = is user's default MFA device for OneLogin.")

  public Boolean getDefault() {
    return _default;
  }


  public void setDefault(Boolean _default) {
    this._default = _default;
  }


  public FactorInner authFactorName(String authFactorName) {
    
    this.authFactorName = authFactorName;
    return this;
  }

   /**
   * \&quot;Official\&quot; authentication factor name, as it appears to administrators in OneLogin.
   * @return authFactorName
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "\"Official\" authentication factor name, as it appears to administrators in OneLogin.")

  public String getAuthFactorName() {
    return authFactorName;
  }


  public void setAuthFactorName(String authFactorName) {
    this.authFactorName = authFactorName;
  }


  public FactorInner typeDisplayName(String typeDisplayName) {
    
    this.typeDisplayName = typeDisplayName;
    return this;
  }

   /**
   * Authentication factor display name as it appears to users upon initial registration, as defined by admins at Settings &gt; Authentication Factors.
   * @return typeDisplayName
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Authentication factor display name as it appears to users upon initial registration, as defined by admins at Settings > Authentication Factors.")

  public String getTypeDisplayName() {
    return typeDisplayName;
  }


  public void setTypeDisplayName(String typeDisplayName) {
    this.typeDisplayName = typeDisplayName;
  }


  public FactorInner userDisplayName(String userDisplayName) {
    
    this.userDisplayName = userDisplayName;
    return this;
  }

   /**
   * Authentication factor display name assigned by users when they enroll the device.
   * @return userDisplayName
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Authentication factor display name assigned by users when they enroll the device.")

  public String getUserDisplayName() {
    return userDisplayName;
  }


  public void setUserDisplayName(String userDisplayName) {
    this.userDisplayName = userDisplayName;
  }


  public FactorInner expiresAt(String expiresAt) {
    
    this.expiresAt = expiresAt;
    return this;
  }

   /**
   * A short lived token that is required to Verify the Factor. This token expires based on the expires_in parameter passed in.
   * @return expiresAt
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A short lived token that is required to Verify the Factor. This token expires based on the expires_in parameter passed in.")

  public String getExpiresAt() {
    return expiresAt;
  }


  public void setExpiresAt(String expiresAt) {
    this.expiresAt = expiresAt;
  }


  public FactorInner factorData(FactorInnerFactorData factorData) {
    
    this.factorData = factorData;
    return this;
  }

   /**
   * Get factorData
   * @return factorData
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public FactorInnerFactorData getFactorData() {
    return factorData;
  }


  public void setFactorData(FactorInnerFactorData factorData) {
    this.factorData = factorData;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    FactorInner factorInner = (FactorInner) o;
    return Objects.equals(this.id, factorInner.id) &&
        Objects.equals(this.status, factorInner.status) &&
        Objects.equals(this._default, factorInner._default) &&
        Objects.equals(this.authFactorName, factorInner.authFactorName) &&
        Objects.equals(this.typeDisplayName, factorInner.typeDisplayName) &&
        Objects.equals(this.userDisplayName, factorInner.userDisplayName) &&
        Objects.equals(this.expiresAt, factorInner.expiresAt) &&
        Objects.equals(this.factorData, factorInner.factorData);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, status, _default, authFactorName, typeDisplayName, userDisplayName, expiresAt, factorData);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class FactorInner {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    status: ").append(toIndentedString(status)).append("\n");
    sb.append("    _default: ").append(toIndentedString(_default)).append("\n");
    sb.append("    authFactorName: ").append(toIndentedString(authFactorName)).append("\n");
    sb.append("    typeDisplayName: ").append(toIndentedString(typeDisplayName)).append("\n");
    sb.append("    userDisplayName: ").append(toIndentedString(userDisplayName)).append("\n");
    sb.append("    expiresAt: ").append(toIndentedString(expiresAt)).append("\n");
    sb.append("    factorData: ").append(toIndentedString(factorData)).append("\n");
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
    openapiFields.add("id");
    openapiFields.add("status");
    openapiFields.add("default");
    openapiFields.add("auth_factor_name");
    openapiFields.add("type_display_name");
    openapiFields.add("user_display_name");
    openapiFields.add("expires_at");
    openapiFields.add("factor_data");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to FactorInner
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (FactorInner.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in FactorInner is not found in the empty JSON string", FactorInner.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!FactorInner.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `FactorInner` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      if ((jsonObj.get("id") != null && !jsonObj.get("id").isJsonNull()) && !jsonObj.get("id").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `id` to be a primitive type in the JSON string but got `%s`", jsonObj.get("id").toString()));
      }
      if ((jsonObj.get("status") != null && !jsonObj.get("status").isJsonNull()) && !jsonObj.get("status").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `status` to be a primitive type in the JSON string but got `%s`", jsonObj.get("status").toString()));
      }
      if ((jsonObj.get("auth_factor_name") != null && !jsonObj.get("auth_factor_name").isJsonNull()) && !jsonObj.get("auth_factor_name").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `auth_factor_name` to be a primitive type in the JSON string but got `%s`", jsonObj.get("auth_factor_name").toString()));
      }
      if ((jsonObj.get("type_display_name") != null && !jsonObj.get("type_display_name").isJsonNull()) && !jsonObj.get("type_display_name").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `type_display_name` to be a primitive type in the JSON string but got `%s`", jsonObj.get("type_display_name").toString()));
      }
      if ((jsonObj.get("user_display_name") != null && !jsonObj.get("user_display_name").isJsonNull()) && !jsonObj.get("user_display_name").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `user_display_name` to be a primitive type in the JSON string but got `%s`", jsonObj.get("user_display_name").toString()));
      }
      if ((jsonObj.get("expires_at") != null && !jsonObj.get("expires_at").isJsonNull()) && !jsonObj.get("expires_at").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `expires_at` to be a primitive type in the JSON string but got `%s`", jsonObj.get("expires_at").toString()));
      }
      // validate the optional field `factor_data`
      if (jsonObj.get("factor_data") != null && !jsonObj.get("factor_data").isJsonNull()) {
        FactorInnerFactorData.validateJsonObject(jsonObj.getAsJsonObject("factor_data"));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!FactorInner.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'FactorInner' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<FactorInner> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(FactorInner.class));

       return (TypeAdapter<T>) new TypeAdapter<FactorInner>() {
           @Override
           public void write(JsonWriter out, FactorInner value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public FactorInner read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of FactorInner given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of FactorInner
  * @throws IOException if the JSON string is invalid with respect to FactorInner
  */
  public static FactorInner fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, FactorInner.class);
  }

 /**
  * Convert an instance of FactorInner to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

