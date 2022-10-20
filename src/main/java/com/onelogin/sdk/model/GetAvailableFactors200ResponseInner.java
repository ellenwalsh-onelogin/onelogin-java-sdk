/*
 * OneLogin API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 3.0.0-beta.1
 * 
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
 * GetAvailableFactors200ResponseInner
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2022-10-20T11:04:19.015422-07:00[America/Los_Angeles]")
public class GetAvailableFactors200ResponseInner {
  public static final String SERIALIZED_NAME_FACTOR_ID = "factor_id";
  @SerializedName(SERIALIZED_NAME_FACTOR_ID)
  private Integer factorId;

  public static final String SERIALIZED_NAME_NAME = "name";
  @SerializedName(SERIALIZED_NAME_NAME)
  private String name;

  public static final String SERIALIZED_NAME_AUTH_FACTOR_NAME = "auth_factor_name";
  @SerializedName(SERIALIZED_NAME_AUTH_FACTOR_NAME)
  private String authFactorName;

  public GetAvailableFactors200ResponseInner() {
  }

  public GetAvailableFactors200ResponseInner factorId(Integer factorId) {
    
    this.factorId = factorId;
    return this;
  }

   /**
   * Identifier for the factor which will be used for user enrollment
   * @return factorId
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Identifier for the factor which will be used for user enrollment")

  public Integer getFactorId() {
    return factorId;
  }


  public void setFactorId(Integer factorId) {
    this.factorId = factorId;
  }


  public GetAvailableFactors200ResponseInner name(String name) {
    
    this.name = name;
    return this;
  }

   /**
   * Authentication factor name, as it appears to administrators in OneLogin.
   * @return name
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Authentication factor name, as it appears to administrators in OneLogin.")

  public String getName() {
    return name;
  }


  public void setName(String name) {
    this.name = name;
  }


  public GetAvailableFactors200ResponseInner authFactorName(String authFactorName) {
    
    this.authFactorName = authFactorName;
    return this;
  }

   /**
   * Internal use only
   * @return authFactorName
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Internal use only")

  public String getAuthFactorName() {
    return authFactorName;
  }


  public void setAuthFactorName(String authFactorName) {
    this.authFactorName = authFactorName;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    GetAvailableFactors200ResponseInner getAvailableFactors200ResponseInner = (GetAvailableFactors200ResponseInner) o;
    return Objects.equals(this.factorId, getAvailableFactors200ResponseInner.factorId) &&
        Objects.equals(this.name, getAvailableFactors200ResponseInner.name) &&
        Objects.equals(this.authFactorName, getAvailableFactors200ResponseInner.authFactorName);
  }

  @Override
  public int hashCode() {
    return Objects.hash(factorId, name, authFactorName);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class GetAvailableFactors200ResponseInner {\n");
    sb.append("    factorId: ").append(toIndentedString(factorId)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    authFactorName: ").append(toIndentedString(authFactorName)).append("\n");
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
    openapiFields.add("factor_id");
    openapiFields.add("name");
    openapiFields.add("auth_factor_name");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to GetAvailableFactors200ResponseInner
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (GetAvailableFactors200ResponseInner.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in GetAvailableFactors200ResponseInner is not found in the empty JSON string", GetAvailableFactors200ResponseInner.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!GetAvailableFactors200ResponseInner.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `GetAvailableFactors200ResponseInner` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      if ((jsonObj.get("name") != null && !jsonObj.get("name").isJsonNull()) && !jsonObj.get("name").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `name` to be a primitive type in the JSON string but got `%s`", jsonObj.get("name").toString()));
      }
      if ((jsonObj.get("auth_factor_name") != null && !jsonObj.get("auth_factor_name").isJsonNull()) && !jsonObj.get("auth_factor_name").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `auth_factor_name` to be a primitive type in the JSON string but got `%s`", jsonObj.get("auth_factor_name").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!GetAvailableFactors200ResponseInner.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'GetAvailableFactors200ResponseInner' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<GetAvailableFactors200ResponseInner> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(GetAvailableFactors200ResponseInner.class));

       return (TypeAdapter<T>) new TypeAdapter<GetAvailableFactors200ResponseInner>() {
           @Override
           public void write(JsonWriter out, GetAvailableFactors200ResponseInner value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public GetAvailableFactors200ResponseInner read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of GetAvailableFactors200ResponseInner given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of GetAvailableFactors200ResponseInner
  * @throws IOException if the JSON string is invalid with respect to GetAvailableFactors200ResponseInner
  */
  public static GetAvailableFactors200ResponseInner fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, GetAvailableFactors200ResponseInner.class);
  }

 /**
  * Convert an instance of GetAvailableFactors200ResponseInner to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

