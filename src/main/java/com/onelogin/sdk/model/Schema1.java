/*
 * OneLogin API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 3.0.0
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
import com.onelogin.sdk.model.Schema1AddedBy;
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
 * Schema1
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2022-10-28T11:26:30.153511-07:00[America/Los_Angeles]")
public class Schema1 {
  public static final String SERIALIZED_NAME_ID = "id";
  @SerializedName(SERIALIZED_NAME_ID)
  private Integer id;

  public static final String SERIALIZED_NAME_NAME = "name";
  @SerializedName(SERIALIZED_NAME_NAME)
  private String name;

  public static final String SERIALIZED_NAME_USERNAME = "username";
  @SerializedName(SERIALIZED_NAME_USERNAME)
  private String username;

  public static final String SERIALIZED_NAME_ADDED_BY = "added_by";
  @SerializedName(SERIALIZED_NAME_ADDED_BY)
  private Schema1AddedBy addedBy;

  public static final String SERIALIZED_NAME_ADDED_AT = "added_at";
  @SerializedName(SERIALIZED_NAME_ADDED_AT)
  private String addedAt;

  public static final String SERIALIZED_NAME_ASSIGNED = "assigned";
  @SerializedName(SERIALIZED_NAME_ASSIGNED)
  private Boolean assigned;

  public Schema1() {
  }

  public Schema1 id(Integer id) {
    
    this.id = id;
    return this;
  }

   /**
   * Get id
   * @return id
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public Integer getId() {
    return id;
  }


  public void setId(Integer id) {
    this.id = id;
  }


  public Schema1 name(String name) {
    
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


  public Schema1 username(String username) {
    
    this.username = username;
    return this;
  }

   /**
   * Get username
   * @return username
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getUsername() {
    return username;
  }


  public void setUsername(String username) {
    this.username = username;
  }


  public Schema1 addedBy(Schema1AddedBy addedBy) {
    
    this.addedBy = addedBy;
    return this;
  }

   /**
   * Get addedBy
   * @return addedBy
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public Schema1AddedBy getAddedBy() {
    return addedBy;
  }


  public void setAddedBy(Schema1AddedBy addedBy) {
    this.addedBy = addedBy;
  }


  public Schema1 addedAt(String addedAt) {
    
    this.addedAt = addedAt;
    return this;
  }

   /**
   * Get addedAt
   * @return addedAt
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getAddedAt() {
    return addedAt;
  }


  public void setAddedAt(String addedAt) {
    this.addedAt = addedAt;
  }


  public Schema1 assigned(Boolean assigned) {
    
    this.assigned = assigned;
    return this;
  }

   /**
   * Indicates if assigned to role or not. Defaults to true.
   * @return assigned
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Indicates if assigned to role or not. Defaults to true.")

  public Boolean getAssigned() {
    return assigned;
  }


  public void setAssigned(Boolean assigned) {
    this.assigned = assigned;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Schema1 schema1 = (Schema1) o;
    return Objects.equals(this.id, schema1.id) &&
        Objects.equals(this.name, schema1.name) &&
        Objects.equals(this.username, schema1.username) &&
        Objects.equals(this.addedBy, schema1.addedBy) &&
        Objects.equals(this.addedAt, schema1.addedAt) &&
        Objects.equals(this.assigned, schema1.assigned);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, name, username, addedBy, addedAt, assigned);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Schema1 {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    username: ").append(toIndentedString(username)).append("\n");
    sb.append("    addedBy: ").append(toIndentedString(addedBy)).append("\n");
    sb.append("    addedAt: ").append(toIndentedString(addedAt)).append("\n");
    sb.append("    assigned: ").append(toIndentedString(assigned)).append("\n");
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
    openapiFields.add("name");
    openapiFields.add("username");
    openapiFields.add("added_by");
    openapiFields.add("added_at");
    openapiFields.add("assigned");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to Schema1
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (Schema1.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in Schema1 is not found in the empty JSON string", Schema1.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!Schema1.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `Schema1` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      if ((jsonObj.get("name") != null && !jsonObj.get("name").isJsonNull()) && !jsonObj.get("name").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `name` to be a primitive type in the JSON string but got `%s`", jsonObj.get("name").toString()));
      }
      if ((jsonObj.get("username") != null && !jsonObj.get("username").isJsonNull()) && !jsonObj.get("username").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `username` to be a primitive type in the JSON string but got `%s`", jsonObj.get("username").toString()));
      }
      // validate the optional field `added_by`
      if (jsonObj.get("added_by") != null && !jsonObj.get("added_by").isJsonNull()) {
        Schema1AddedBy.validateJsonObject(jsonObj.getAsJsonObject("added_by"));
      }
      if ((jsonObj.get("added_at") != null && !jsonObj.get("added_at").isJsonNull()) && !jsonObj.get("added_at").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `added_at` to be a primitive type in the JSON string but got `%s`", jsonObj.get("added_at").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!Schema1.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'Schema1' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<Schema1> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(Schema1.class));

       return (TypeAdapter<T>) new TypeAdapter<Schema1>() {
           @Override
           public void write(JsonWriter out, Schema1 value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public Schema1 read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of Schema1 given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of Schema1
  * @throws IOException if the JSON string is invalid with respect to Schema1
  */
  public static Schema1 fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, Schema1.class);
  }

 /**
  * Convert an instance of Schema1 to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

