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
import com.onelogin.client.model.SamlAppAllOfParametersSamlUsername;
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
 * SamlAppAllOfParameters
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2023-03-16T13:09:58.336938-07:00[America/Los_Angeles]")
public class SamlAppAllOfParameters {
  public static final String SERIALIZED_NAME_SAML_USERNAME = "saml_username";
  @SerializedName(SERIALIZED_NAME_SAML_USERNAME)
  private SamlAppAllOfParametersSamlUsername samlUsername;

  public SamlAppAllOfParameters() {
  }

  public SamlAppAllOfParameters samlUsername(SamlAppAllOfParametersSamlUsername samlUsername) {
    
    this.samlUsername = samlUsername;
    return this;
  }

   /**
   * Get samlUsername
   * @return samlUsername
  **/
  @javax.annotation.Nonnull

  public SamlAppAllOfParametersSamlUsername getSamlUsername() {
    return samlUsername;
  }


  public void setSamlUsername(SamlAppAllOfParametersSamlUsername samlUsername) {
    this.samlUsername = samlUsername;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    SamlAppAllOfParameters samlAppAllOfParameters = (SamlAppAllOfParameters) o;
    return Objects.equals(this.samlUsername, samlAppAllOfParameters.samlUsername);
  }

  @Override
  public int hashCode() {
    return Objects.hash(samlUsername);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class SamlAppAllOfParameters {\n");
    sb.append("    samlUsername: ").append(toIndentedString(samlUsername)).append("\n");
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
    openapiFields.add("saml_username");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
    openapiRequiredFields.add("saml_username");
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to SamlAppAllOfParameters
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (!SamlAppAllOfParameters.openapiRequiredFields.isEmpty()) { // has required fields but JSON object is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in SamlAppAllOfParameters is not found in the empty JSON string", SamlAppAllOfParameters.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!SamlAppAllOfParameters.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `SamlAppAllOfParameters` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }

      // check to make sure all required properties/fields are present in the JSON string
      for (String requiredField : SamlAppAllOfParameters.openapiRequiredFields) {
        if (jsonObj.get(requiredField) == null) {
          throw new IllegalArgumentException(String.format("The required field `%s` is not found in the JSON string: %s", requiredField, jsonObj.toString()));
        }
      }
      // validate the required field `saml_username`
      SamlAppAllOfParametersSamlUsername.validateJsonObject(jsonObj.getAsJsonObject("saml_username"));
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!SamlAppAllOfParameters.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'SamlAppAllOfParameters' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<SamlAppAllOfParameters> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(SamlAppAllOfParameters.class));

       return (TypeAdapter<T>) new TypeAdapter<SamlAppAllOfParameters>() {
           @Override
           public void write(JsonWriter out, SamlAppAllOfParameters value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public SamlAppAllOfParameters read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of SamlAppAllOfParameters given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of SamlAppAllOfParameters
  * @throws IOException if the JSON string is invalid with respect to SamlAppAllOfParameters
  */
  public static SamlAppAllOfParameters fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, SamlAppAllOfParameters.class);
  }

 /**
  * Convert an instance of SamlAppAllOfParameters to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}
