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
 * Action
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2022-10-28T11:26:30.153511-07:00[America/Los_Angeles]")
public class Action {
  public static final String SERIALIZED_NAME_ACTION = "action";
  @SerializedName(SERIALIZED_NAME_ACTION)
  private String action;

  public static final String SERIALIZED_NAME_VALUE = "value";
  @SerializedName(SERIALIZED_NAME_VALUE)
  private List<String> value = null;

  public static final String SERIALIZED_NAME_EXPRESSION = "expression";
  @SerializedName(SERIALIZED_NAME_EXPRESSION)
  private String expression;

  public static final String SERIALIZED_NAME_SCRIPLET = "scriplet";
  @SerializedName(SERIALIZED_NAME_SCRIPLET)
  private String scriplet;

  public static final String SERIALIZED_NAME_MACRO = "macro";
  @SerializedName(SERIALIZED_NAME_MACRO)
  private String macro;

  public Action() {
  }

  public Action action(String action) {
    
    this.action = action;
    return this;
  }

   /**
   * The action to apply
   * @return action
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The action to apply")

  public String getAction() {
    return action;
  }


  public void setAction(String action) {
    this.action = action;
  }


  public Action value(List<String> value) {
    
    this.value = value;
    return this;
  }

  public Action addValueItem(String valueItem) {
    if (this.value == null) {
      this.value = new ArrayList<>();
    }
    this.value.add(valueItem);
    return this;
  }

   /**
   * Only applicable to provisioned and set_* actions. Items in the array will be a plain text string or valid value for the selected action.
   * @return value
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Only applicable to provisioned and set_* actions. Items in the array will be a plain text string or valid value for the selected action.")

  public List<String> getValue() {
    return value;
  }


  public void setValue(List<String> value) {
    this.value = value;
  }


  public Action expression(String expression) {
    
    this.expression = expression;
    return this;
  }

   /**
   * A regular expression to extract a value. Applies to provisionable, multi-selects, and string actions.
   * @return expression
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A regular expression to extract a value. Applies to provisionable, multi-selects, and string actions.")

  public String getExpression() {
    return expression;
  }


  public void setExpression(String expression) {
    this.expression = expression;
  }


  public Action scriplet(String scriplet) {
    
    this.scriplet = scriplet;
    return this;
  }

   /**
   * A hash containing scriptlet code that returns a value.
   * @return scriplet
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A hash containing scriptlet code that returns a value.")

  public String getScriplet() {
    return scriplet;
  }


  public void setScriplet(String scriplet) {
    this.scriplet = scriplet;
  }


  public Action macro(String macro) {
    
    this.macro = macro;
    return this;
  }

   /**
   * A template to construct a value. Applies to default, string, and list actions.
   * @return macro
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "A template to construct a value. Applies to default, string, and list actions.")

  public String getMacro() {
    return macro;
  }


  public void setMacro(String macro) {
    this.macro = macro;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Action action = (Action) o;
    return Objects.equals(this.action, action.action) &&
        Objects.equals(this.value, action.value) &&
        Objects.equals(this.expression, action.expression) &&
        Objects.equals(this.scriplet, action.scriplet) &&
        Objects.equals(this.macro, action.macro);
  }

  @Override
  public int hashCode() {
    return Objects.hash(action, value, expression, scriplet, macro);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Action {\n");
    sb.append("    action: ").append(toIndentedString(action)).append("\n");
    sb.append("    value: ").append(toIndentedString(value)).append("\n");
    sb.append("    expression: ").append(toIndentedString(expression)).append("\n");
    sb.append("    scriplet: ").append(toIndentedString(scriplet)).append("\n");
    sb.append("    macro: ").append(toIndentedString(macro)).append("\n");
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
    openapiFields.add("action");
    openapiFields.add("value");
    openapiFields.add("expression");
    openapiFields.add("scriplet");
    openapiFields.add("macro");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to Action
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (Action.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in Action is not found in the empty JSON string", Action.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!Action.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `Action` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      if ((jsonObj.get("action") != null && !jsonObj.get("action").isJsonNull()) && !jsonObj.get("action").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `action` to be a primitive type in the JSON string but got `%s`", jsonObj.get("action").toString()));
      }
      // ensure the json data is an array
      if ((jsonObj.get("value") != null && !jsonObj.get("value").isJsonNull()) && !jsonObj.get("value").isJsonArray()) {
        throw new IllegalArgumentException(String.format("Expected the field `value` to be an array in the JSON string but got `%s`", jsonObj.get("value").toString()));
      }
      if ((jsonObj.get("expression") != null && !jsonObj.get("expression").isJsonNull()) && !jsonObj.get("expression").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `expression` to be a primitive type in the JSON string but got `%s`", jsonObj.get("expression").toString()));
      }
      if ((jsonObj.get("scriplet") != null && !jsonObj.get("scriplet").isJsonNull()) && !jsonObj.get("scriplet").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `scriplet` to be a primitive type in the JSON string but got `%s`", jsonObj.get("scriplet").toString()));
      }
      if ((jsonObj.get("macro") != null && !jsonObj.get("macro").isJsonNull()) && !jsonObj.get("macro").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `macro` to be a primitive type in the JSON string but got `%s`", jsonObj.get("macro").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!Action.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'Action' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<Action> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(Action.class));

       return (TypeAdapter<T>) new TypeAdapter<Action>() {
           @Override
           public void write(JsonWriter out, Action value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public Action read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of Action given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of Action
  * @throws IOException if the JSON string is invalid with respect to Action
  */
  public static Action fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, Action.class);
  }

 /**
  * Convert an instance of Action to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

