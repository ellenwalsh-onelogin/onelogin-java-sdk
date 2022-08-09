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
import java.util.ArrayList;
import java.util.List;
import org.openapitools.client.model.Action;
import org.openapitools.client.model.Condition;

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
 * Rule
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2022-08-09T11:03:49.744981-07:00[America/Los_Angeles]")
public class Rule {
  public static final String SERIALIZED_NAME_ID = "id";
  @SerializedName(SERIALIZED_NAME_ID)
  private Integer id;

  public static final String SERIALIZED_NAME_NAME = "name";
  @SerializedName(SERIALIZED_NAME_NAME)
  private String name;

  /**
   * Indicates how conditions should be matched.
   */
  @JsonAdapter(MatchEnum.Adapter.class)
  public enum MatchEnum {
    ALL("all"),
    
    ANY("any");

    private String value;

    MatchEnum(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public static MatchEnum fromValue(String value) {
      for (MatchEnum b : MatchEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }

    public static class Adapter extends TypeAdapter<MatchEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final MatchEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public MatchEnum read(final JsonReader jsonReader) throws IOException {
        String value =  jsonReader.nextString();
        return MatchEnum.fromValue(value);
      }
    }
  }

  public static final String SERIALIZED_NAME_MATCH = "match";
  @SerializedName(SERIALIZED_NAME_MATCH)
  private MatchEnum match;

  public static final String SERIALIZED_NAME_ENABLED = "enabled";
  @SerializedName(SERIALIZED_NAME_ENABLED)
  private Boolean enabled;

  public static final String SERIALIZED_NAME_POSITION = "position";
  @SerializedName(SERIALIZED_NAME_POSITION)
  private Integer position;

  public static final String SERIALIZED_NAME_CONDITIONS = "conditions";
  @SerializedName(SERIALIZED_NAME_CONDITIONS)
  private List<Condition> conditions = null;

  public static final String SERIALIZED_NAME_ACTIONS = "actions";
  @SerializedName(SERIALIZED_NAME_ACTIONS)
  private List<Action> actions = null;

  public Rule() { 
  }

  public Rule id(Integer id) {
    
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


  public Rule name(String name) {
    
    this.name = name;
    return this;
  }

   /**
   * The name of the rule.
   * @return name
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "The name of the rule.")

  public String getName() {
    return name;
  }


  public void setName(String name) {
    this.name = name;
  }


  public Rule match(MatchEnum match) {
    
    this.match = match;
    return this;
  }

   /**
   * Indicates how conditions should be matched.
   * @return match
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Indicates how conditions should be matched.")

  public MatchEnum getMatch() {
    return match;
  }


  public void setMatch(MatchEnum match) {
    this.match = match;
  }


  public Rule enabled(Boolean enabled) {
    
    this.enabled = enabled;
    return this;
  }

   /**
   * Indicates if the rule is enabled or not.
   * @return enabled
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Indicates if the rule is enabled or not.")

  public Boolean getEnabled() {
    return enabled;
  }


  public void setEnabled(Boolean enabled) {
    this.enabled = enabled;
  }


  public Rule position(Integer position) {
    
    this.position = position;
    return this;
  }

   /**
   * Indicates the order of the rule. When &#x60;null&#x60; this will default to last position.
   * @return position
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "Indicates the order of the rule. When `null` this will default to last position.")

  public Integer getPosition() {
    return position;
  }


  public void setPosition(Integer position) {
    this.position = position;
  }


  public Rule conditions(List<Condition> conditions) {
    
    this.conditions = conditions;
    return this;
  }

  public Rule addConditionsItem(Condition conditionsItem) {
    if (this.conditions == null) {
      this.conditions = new ArrayList<>();
    }
    this.conditions.add(conditionsItem);
    return this;
  }

   /**
   * An array of conditions that the user must meet in order for the rule to be applied.
   * @return conditions
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "An array of conditions that the user must meet in order for the rule to be applied.")

  public List<Condition> getConditions() {
    return conditions;
  }


  public void setConditions(List<Condition> conditions) {
    this.conditions = conditions;
  }


  public Rule actions(List<Action> actions) {
    
    this.actions = actions;
    return this;
  }

  public Rule addActionsItem(Action actionsItem) {
    if (this.actions == null) {
      this.actions = new ArrayList<>();
    }
    this.actions.add(actionsItem);
    return this;
  }

   /**
   * An array of actions that will be applied to the users that are matched by the conditions.
   * @return actions
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "An array of actions that will be applied to the users that are matched by the conditions.")

  public List<Action> getActions() {
    return actions;
  }


  public void setActions(List<Action> actions) {
    this.actions = actions;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Rule rule = (Rule) o;
    return Objects.equals(this.id, rule.id) &&
        Objects.equals(this.name, rule.name) &&
        Objects.equals(this.match, rule.match) &&
        Objects.equals(this.enabled, rule.enabled) &&
        Objects.equals(this.position, rule.position) &&
        Objects.equals(this.conditions, rule.conditions) &&
        Objects.equals(this.actions, rule.actions);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, name, match, enabled, position, conditions, actions);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Rule {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    match: ").append(toIndentedString(match)).append("\n");
    sb.append("    enabled: ").append(toIndentedString(enabled)).append("\n");
    sb.append("    position: ").append(toIndentedString(position)).append("\n");
    sb.append("    conditions: ").append(toIndentedString(conditions)).append("\n");
    sb.append("    actions: ").append(toIndentedString(actions)).append("\n");
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
    openapiFields.add("match");
    openapiFields.add("enabled");
    openapiFields.add("position");
    openapiFields.add("conditions");
    openapiFields.add("actions");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to Rule
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (Rule.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in Rule is not found in the empty JSON string", Rule.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!Rule.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `Rule` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      if (jsonObj.get("name") != null && !jsonObj.get("name").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `name` to be a primitive type in the JSON string but got `%s`", jsonObj.get("name").toString()));
      }
      if (jsonObj.get("match") != null && !jsonObj.get("match").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `match` to be a primitive type in the JSON string but got `%s`", jsonObj.get("match").toString()));
      }
      JsonArray jsonArrayconditions = jsonObj.getAsJsonArray("conditions");
      if (jsonArrayconditions != null) {
        // ensure the json data is an array
        if (!jsonObj.get("conditions").isJsonArray()) {
          throw new IllegalArgumentException(String.format("Expected the field `conditions` to be an array in the JSON string but got `%s`", jsonObj.get("conditions").toString()));
        }

        // validate the optional field `conditions` (array)
        for (int i = 0; i < jsonArrayconditions.size(); i++) {
          Condition.validateJsonObject(jsonArrayconditions.get(i).getAsJsonObject());
        };
      }
      JsonArray jsonArrayactions = jsonObj.getAsJsonArray("actions");
      if (jsonArrayactions != null) {
        // ensure the json data is an array
        if (!jsonObj.get("actions").isJsonArray()) {
          throw new IllegalArgumentException(String.format("Expected the field `actions` to be an array in the JSON string but got `%s`", jsonObj.get("actions").toString()));
        }

        // validate the optional field `actions` (array)
        for (int i = 0; i < jsonArrayactions.size(); i++) {
          Action.validateJsonObject(jsonArrayactions.get(i).getAsJsonObject());
        };
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!Rule.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'Rule' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<Rule> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(Rule.class));

       return (TypeAdapter<T>) new TypeAdapter<Rule>() {
           @Override
           public void write(JsonWriter out, Rule value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public Rule read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of Rule given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of Rule
  * @throws IOException if the JSON string is invalid with respect to Rule
  */
  public static Rule fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, Rule.class);
  }

 /**
  * Convert an instance of Rule to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

