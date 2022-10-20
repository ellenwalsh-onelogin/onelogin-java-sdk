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
import java.util.ArrayList;
import java.util.List;

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
 * ListAuthorizationServers200ResponseInnerConfiguration
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2022-10-20T11:04:19.015422-07:00[America/Los_Angeles]")
public class ListAuthorizationServers200ResponseInnerConfiguration {
  public static final String SERIALIZED_NAME_RESOURCE_IDENTIFIER = "resource_identifier";
  @SerializedName(SERIALIZED_NAME_RESOURCE_IDENTIFIER)
  private String resourceIdentifier;

  public static final String SERIALIZED_NAME_AUDIENCES = "audiences";
  @SerializedName(SERIALIZED_NAME_AUDIENCES)
  private List<String> audiences = null;

  public ListAuthorizationServers200ResponseInnerConfiguration() {
  }

  public ListAuthorizationServers200ResponseInnerConfiguration resourceIdentifier(String resourceIdentifier) {
    
    this.resourceIdentifier = resourceIdentifier;
    return this;
  }

   /**
   * Get resourceIdentifier
   * @return resourceIdentifier
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getResourceIdentifier() {
    return resourceIdentifier;
  }


  public void setResourceIdentifier(String resourceIdentifier) {
    this.resourceIdentifier = resourceIdentifier;
  }


  public ListAuthorizationServers200ResponseInnerConfiguration audiences(List<String> audiences) {
    
    this.audiences = audiences;
    return this;
  }

  public ListAuthorizationServers200ResponseInnerConfiguration addAudiencesItem(String audiencesItem) {
    if (this.audiences == null) {
      this.audiences = new ArrayList<>();
    }
    this.audiences.add(audiencesItem);
    return this;
  }

   /**
   * Get audiences
   * @return audiences
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public List<String> getAudiences() {
    return audiences;
  }


  public void setAudiences(List<String> audiences) {
    this.audiences = audiences;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ListAuthorizationServers200ResponseInnerConfiguration listAuthorizationServers200ResponseInnerConfiguration = (ListAuthorizationServers200ResponseInnerConfiguration) o;
    return Objects.equals(this.resourceIdentifier, listAuthorizationServers200ResponseInnerConfiguration.resourceIdentifier) &&
        Objects.equals(this.audiences, listAuthorizationServers200ResponseInnerConfiguration.audiences);
  }

  @Override
  public int hashCode() {
    return Objects.hash(resourceIdentifier, audiences);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ListAuthorizationServers200ResponseInnerConfiguration {\n");
    sb.append("    resourceIdentifier: ").append(toIndentedString(resourceIdentifier)).append("\n");
    sb.append("    audiences: ").append(toIndentedString(audiences)).append("\n");
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
    openapiFields.add("resource_identifier");
    openapiFields.add("audiences");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to ListAuthorizationServers200ResponseInnerConfiguration
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (ListAuthorizationServers200ResponseInnerConfiguration.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in ListAuthorizationServers200ResponseInnerConfiguration is not found in the empty JSON string", ListAuthorizationServers200ResponseInnerConfiguration.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!ListAuthorizationServers200ResponseInnerConfiguration.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `ListAuthorizationServers200ResponseInnerConfiguration` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      if ((jsonObj.get("resource_identifier") != null && !jsonObj.get("resource_identifier").isJsonNull()) && !jsonObj.get("resource_identifier").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `resource_identifier` to be a primitive type in the JSON string but got `%s`", jsonObj.get("resource_identifier").toString()));
      }
      // ensure the json data is an array
      if ((jsonObj.get("audiences") != null && !jsonObj.get("audiences").isJsonNull()) && !jsonObj.get("audiences").isJsonArray()) {
        throw new IllegalArgumentException(String.format("Expected the field `audiences` to be an array in the JSON string but got `%s`", jsonObj.get("audiences").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!ListAuthorizationServers200ResponseInnerConfiguration.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'ListAuthorizationServers200ResponseInnerConfiguration' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<ListAuthorizationServers200ResponseInnerConfiguration> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(ListAuthorizationServers200ResponseInnerConfiguration.class));

       return (TypeAdapter<T>) new TypeAdapter<ListAuthorizationServers200ResponseInnerConfiguration>() {
           @Override
           public void write(JsonWriter out, ListAuthorizationServers200ResponseInnerConfiguration value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public ListAuthorizationServers200ResponseInnerConfiguration read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of ListAuthorizationServers200ResponseInnerConfiguration given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of ListAuthorizationServers200ResponseInnerConfiguration
  * @throws IOException if the JSON string is invalid with respect to ListAuthorizationServers200ResponseInnerConfiguration
  */
  public static ListAuthorizationServers200ResponseInnerConfiguration fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, ListAuthorizationServers200ResponseInnerConfiguration.class);
  }

 /**
  * Convert an instance of ListAuthorizationServers200ResponseInnerConfiguration to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

