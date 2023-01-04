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
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;
import java.math.BigDecimal;
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
 * GetRiskScore200Response
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2023-01-04T14:04:05.007954-08:00[America/Los_Angeles]")
public class GetRiskScore200Response {
  public static final String SERIALIZED_NAME_SCORE = "score";
  @SerializedName(SERIALIZED_NAME_SCORE)
  private BigDecimal score;

  public static final String SERIALIZED_NAME_TRIGGERS = "triggers";
  @SerializedName(SERIALIZED_NAME_TRIGGERS)
  private List<String> triggers = null;

  public GetRiskScore200Response() {
  }

  public GetRiskScore200Response score(BigDecimal score) {
    
    this.score = score;
    return this;
  }

   /**
   * A risk score 0 is low risk and 100 is the highest risk level possible.
   * minimum: 0.0
   * maximum: 100.0
   * @return score
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A risk score 0 is low risk and 100 is the highest risk level possible.")

  public BigDecimal getScore() {
    return score;
  }


  public void setScore(BigDecimal score) {
    this.score = score;
  }


  public GetRiskScore200Response triggers(List<String> triggers) {
    
    this.triggers = triggers;
    return this;
  }

  public GetRiskScore200Response addTriggersItem(String triggersItem) {
    if (this.triggers == null) {
      this.triggers = new ArrayList<>();
    }
    this.triggers.add(triggersItem);
    return this;
  }

   /**
   * Triggers are indicators of some of the key items that influenced the risk score.
   * @return triggers
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Triggers are indicators of some of the key items that influenced the risk score.")

  public List<String> getTriggers() {
    return triggers;
  }


  public void setTriggers(List<String> triggers) {
    this.triggers = triggers;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    GetRiskScore200Response getRiskScore200Response = (GetRiskScore200Response) o;
    return Objects.equals(this.score, getRiskScore200Response.score) &&
        Objects.equals(this.triggers, getRiskScore200Response.triggers);
  }

  @Override
  public int hashCode() {
    return Objects.hash(score, triggers);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class GetRiskScore200Response {\n");
    sb.append("    score: ").append(toIndentedString(score)).append("\n");
    sb.append("    triggers: ").append(toIndentedString(triggers)).append("\n");
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
    openapiFields.add("score");
    openapiFields.add("triggers");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to GetRiskScore200Response
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (GetRiskScore200Response.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in GetRiskScore200Response is not found in the empty JSON string", GetRiskScore200Response.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!GetRiskScore200Response.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `GetRiskScore200Response` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      // ensure the json data is an array
      if ((jsonObj.get("triggers") != null && !jsonObj.get("triggers").isJsonNull()) && !jsonObj.get("triggers").isJsonArray()) {
        throw new IllegalArgumentException(String.format("Expected the field `triggers` to be an array in the JSON string but got `%s`", jsonObj.get("triggers").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!GetRiskScore200Response.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'GetRiskScore200Response' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<GetRiskScore200Response> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(GetRiskScore200Response.class));

       return (TypeAdapter<T>) new TypeAdapter<GetRiskScore200Response>() {
           @Override
           public void write(JsonWriter out, GetRiskScore200Response value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public GetRiskScore200Response read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of GetRiskScore200Response given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of GetRiskScore200Response
  * @throws IOException if the JSON string is invalid with respect to GetRiskScore200Response
  */
  public static GetRiskScore200Response fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, GetRiskScore200Response.class);
  }

 /**
  * Convert an instance of GetRiskScore200Response to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

