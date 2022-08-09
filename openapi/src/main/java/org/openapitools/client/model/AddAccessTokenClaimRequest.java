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
 * AddAccessTokenClaimRequest
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2022-08-09T11:03:49.744981-07:00[America/Los_Angeles]")
public class AddAccessTokenClaimRequest {
  public static final String SERIALIZED_NAME_NAME = "name";
  @SerializedName(SERIALIZED_NAME_NAME)
  private String name;

  public static final String SERIALIZED_NAME_USER_ATTRIBUTE_MAPPINGS = "user_attribute_mappings";
  @SerializedName(SERIALIZED_NAME_USER_ATTRIBUTE_MAPPINGS)
  private String userAttributeMappings;

  public static final String SERIALIZED_NAME_USER_ATTRIBUTE_MACROS = "user_attribute_macros";
  @SerializedName(SERIALIZED_NAME_USER_ATTRIBUTE_MACROS)
  private String userAttributeMacros;

  public AddAccessTokenClaimRequest() { 
  }

  public AddAccessTokenClaimRequest name(String name) {
    
    this.name = name;
    return this;
  }

   /**
   * Get name
   * @return name
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getName() {
    return name;
  }


  public void setName(String name) {
    this.name = name;
  }


  public AddAccessTokenClaimRequest userAttributeMappings(String userAttributeMappings) {
    
    this.userAttributeMappings = userAttributeMappings;
    return this;
  }

   /**
   * Get userAttributeMappings
   * @return userAttributeMappings
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getUserAttributeMappings() {
    return userAttributeMappings;
  }


  public void setUserAttributeMappings(String userAttributeMappings) {
    this.userAttributeMappings = userAttributeMappings;
  }


  public AddAccessTokenClaimRequest userAttributeMacros(String userAttributeMacros) {
    
    this.userAttributeMacros = userAttributeMacros;
    return this;
  }

   /**
   * Get userAttributeMacros
   * @return userAttributeMacros
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getUserAttributeMacros() {
    return userAttributeMacros;
  }


  public void setUserAttributeMacros(String userAttributeMacros) {
    this.userAttributeMacros = userAttributeMacros;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AddAccessTokenClaimRequest addAccessTokenClaimRequest = (AddAccessTokenClaimRequest) o;
    return Objects.equals(this.name, addAccessTokenClaimRequest.name) &&
        Objects.equals(this.userAttributeMappings, addAccessTokenClaimRequest.userAttributeMappings) &&
        Objects.equals(this.userAttributeMacros, addAccessTokenClaimRequest.userAttributeMacros);
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, userAttributeMappings, userAttributeMacros);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AddAccessTokenClaimRequest {\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    userAttributeMappings: ").append(toIndentedString(userAttributeMappings)).append("\n");
    sb.append("    userAttributeMacros: ").append(toIndentedString(userAttributeMacros)).append("\n");
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
    openapiFields.add("name");
    openapiFields.add("user_attribute_mappings");
    openapiFields.add("user_attribute_macros");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to AddAccessTokenClaimRequest
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (AddAccessTokenClaimRequest.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in AddAccessTokenClaimRequest is not found in the empty JSON string", AddAccessTokenClaimRequest.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!AddAccessTokenClaimRequest.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `AddAccessTokenClaimRequest` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      if (jsonObj.get("name") != null && !jsonObj.get("name").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `name` to be a primitive type in the JSON string but got `%s`", jsonObj.get("name").toString()));
      }
      if (jsonObj.get("user_attribute_mappings") != null && !jsonObj.get("user_attribute_mappings").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `user_attribute_mappings` to be a primitive type in the JSON string but got `%s`", jsonObj.get("user_attribute_mappings").toString()));
      }
      if (jsonObj.get("user_attribute_macros") != null && !jsonObj.get("user_attribute_macros").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `user_attribute_macros` to be a primitive type in the JSON string but got `%s`", jsonObj.get("user_attribute_macros").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!AddAccessTokenClaimRequest.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'AddAccessTokenClaimRequest' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<AddAccessTokenClaimRequest> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(AddAccessTokenClaimRequest.class));

       return (TypeAdapter<T>) new TypeAdapter<AddAccessTokenClaimRequest>() {
           @Override
           public void write(JsonWriter out, AddAccessTokenClaimRequest value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public AddAccessTokenClaimRequest read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of AddAccessTokenClaimRequest given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of AddAccessTokenClaimRequest
  * @throws IOException if the JSON string is invalid with respect to AddAccessTokenClaimRequest
  */
  public static AddAccessTokenClaimRequest fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, AddAccessTokenClaimRequest.class);
  }

 /**
  * Convert an instance of AddAccessTokenClaimRequest to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}
