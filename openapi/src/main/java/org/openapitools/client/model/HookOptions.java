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
 * A set of attributes allow control over the information that is included in the hook context.
 */
@ApiModel(description = "A set of attributes allow control over the information that is included in the hook context.")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2022-08-09T11:03:49.744981-07:00[America/Los_Angeles]")
public class HookOptions {
  public static final String SERIALIZED_NAME_RISK_ENABLED = "risk_enabled";
  @SerializedName(SERIALIZED_NAME_RISK_ENABLED)
  private Boolean riskEnabled;

  public static final String SERIALIZED_NAME_LOCATION_ENABLED = "location_enabled";
  @SerializedName(SERIALIZED_NAME_LOCATION_ENABLED)
  private Boolean locationEnabled;

  public static final String SERIALIZED_NAME_MFA_DEVICE_INFO_ENABLED = "mfa_device_info_enabled";
  @SerializedName(SERIALIZED_NAME_MFA_DEVICE_INFO_ENABLED)
  private Boolean mfaDeviceInfoEnabled;

  public HookOptions() { 
  }

  public HookOptions riskEnabled(Boolean riskEnabled) {
    
    this.riskEnabled = riskEnabled;
    return this;
  }

   /**
   * Get riskEnabled
   * @return riskEnabled
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public Boolean getRiskEnabled() {
    return riskEnabled;
  }


  public void setRiskEnabled(Boolean riskEnabled) {
    this.riskEnabled = riskEnabled;
  }


  public HookOptions locationEnabled(Boolean locationEnabled) {
    
    this.locationEnabled = locationEnabled;
    return this;
  }

   /**
   * Get locationEnabled
   * @return locationEnabled
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public Boolean getLocationEnabled() {
    return locationEnabled;
  }


  public void setLocationEnabled(Boolean locationEnabled) {
    this.locationEnabled = locationEnabled;
  }


  public HookOptions mfaDeviceInfoEnabled(Boolean mfaDeviceInfoEnabled) {
    
    this.mfaDeviceInfoEnabled = mfaDeviceInfoEnabled;
    return this;
  }

   /**
   * Get mfaDeviceInfoEnabled
   * @return mfaDeviceInfoEnabled
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public Boolean getMfaDeviceInfoEnabled() {
    return mfaDeviceInfoEnabled;
  }


  public void setMfaDeviceInfoEnabled(Boolean mfaDeviceInfoEnabled) {
    this.mfaDeviceInfoEnabled = mfaDeviceInfoEnabled;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    HookOptions hookOptions = (HookOptions) o;
    return Objects.equals(this.riskEnabled, hookOptions.riskEnabled) &&
        Objects.equals(this.locationEnabled, hookOptions.locationEnabled) &&
        Objects.equals(this.mfaDeviceInfoEnabled, hookOptions.mfaDeviceInfoEnabled);
  }

  @Override
  public int hashCode() {
    return Objects.hash(riskEnabled, locationEnabled, mfaDeviceInfoEnabled);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class HookOptions {\n");
    sb.append("    riskEnabled: ").append(toIndentedString(riskEnabled)).append("\n");
    sb.append("    locationEnabled: ").append(toIndentedString(locationEnabled)).append("\n");
    sb.append("    mfaDeviceInfoEnabled: ").append(toIndentedString(mfaDeviceInfoEnabled)).append("\n");
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
    openapiFields.add("risk_enabled");
    openapiFields.add("location_enabled");
    openapiFields.add("mfa_device_info_enabled");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to HookOptions
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (HookOptions.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in HookOptions is not found in the empty JSON string", HookOptions.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!HookOptions.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `HookOptions` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!HookOptions.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'HookOptions' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<HookOptions> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(HookOptions.class));

       return (TypeAdapter<T>) new TypeAdapter<HookOptions>() {
           @Override
           public void write(JsonWriter out, HookOptions value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public HookOptions read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of HookOptions given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of HookOptions
  * @throws IOException if the JSON string is invalid with respect to HookOptions
  */
  public static HookOptions fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, HookOptions.class);
  }

 /**
  * Convert an instance of HookOptions to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

