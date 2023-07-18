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
import com.onelogin.client.model.BrandBackground;
import com.onelogin.client.model.BrandLogo;
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
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.onelogin.client.JSON;

/**
 * Brand
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen", date = "2023-07-18T11:53:48.226013-07:00[America/Los_Angeles]")
public class Brand {
  public static final String SERIALIZED_NAME_ID = "id";
  @SerializedName(SERIALIZED_NAME_ID)
  private Integer id;

  public static final String SERIALIZED_NAME_ENABLED = "enabled";
  @SerializedName(SERIALIZED_NAME_ENABLED)
  private Boolean enabled = false;

  public static final String SERIALIZED_NAME_CUSTOM_SUPPORT_ENABLED = "custom_support_enabled";
  @SerializedName(SERIALIZED_NAME_CUSTOM_SUPPORT_ENABLED)
  private Boolean customSupportEnabled;

  public static final String SERIALIZED_NAME_CUSTOM_COLOR = "custom_color";
  @SerializedName(SERIALIZED_NAME_CUSTOM_COLOR)
  private String customColor;

  public static final String SERIALIZED_NAME_CUSTOM_ACCENT_COLOR = "custom_accent_color";
  @SerializedName(SERIALIZED_NAME_CUSTOM_ACCENT_COLOR)
  private String customAccentColor;

  public static final String SERIALIZED_NAME_CUSTOM_MASKING_COLOR = "custom_masking_color";
  @SerializedName(SERIALIZED_NAME_CUSTOM_MASKING_COLOR)
  private String customMaskingColor;

  public static final String SERIALIZED_NAME_CUSTOM_MASKING_OPACITY = "custom_masking_opacity";
  @SerializedName(SERIALIZED_NAME_CUSTOM_MASKING_OPACITY)
  private Integer customMaskingOpacity;

  public static final String SERIALIZED_NAME_MFA_ENROLLMENT_MESSAGE = "mfa_enrollment_message";
  @SerializedName(SERIALIZED_NAME_MFA_ENROLLMENT_MESSAGE)
  private String mfaEnrollmentMessage;

  public static final String SERIALIZED_NAME_ENABLE_CUSTOM_LABEL_FOR_LOGIN_SCREEN = "enable_custom_label_for_login_screen";
  @SerializedName(SERIALIZED_NAME_ENABLE_CUSTOM_LABEL_FOR_LOGIN_SCREEN)
  private Boolean enableCustomLabelForLoginScreen;

  public static final String SERIALIZED_NAME_CUSTOM_LABEL_TEXT_FOR_LOGIN_SCREEN = "custom_label_text_for_login_screen";
  @SerializedName(SERIALIZED_NAME_CUSTOM_LABEL_TEXT_FOR_LOGIN_SCREEN)
  private String customLabelTextForLoginScreen;

  public static final String SERIALIZED_NAME_LOGIN_INSTRUCTION = "login_instruction";
  @SerializedName(SERIALIZED_NAME_LOGIN_INSTRUCTION)
  private String loginInstruction;

  public static final String SERIALIZED_NAME_LOGIN_INSTRUCTION_TITLE = "login_instruction_title";
  @SerializedName(SERIALIZED_NAME_LOGIN_INSTRUCTION_TITLE)
  private String loginInstructionTitle;

  public static final String SERIALIZED_NAME_HIDE_ONELOGIN_FOOTER = "hide_onelogin_footer";
  @SerializedName(SERIALIZED_NAME_HIDE_ONELOGIN_FOOTER)
  private Boolean hideOneloginFooter;

  public static final String SERIALIZED_NAME_BACKGROUND = "background";
  @SerializedName(SERIALIZED_NAME_BACKGROUND)
  private BrandBackground background;

  public static final String SERIALIZED_NAME_LOGO = "logo";
  @SerializedName(SERIALIZED_NAME_LOGO)
  private BrandLogo logo;

  public Brand() {
  }

  public Brand id(Integer id) {
    
    this.id = id;
    return this;
  }

   /**
   * Get id
   * @return id
  **/
  @javax.annotation.Nonnull
  public Integer getId() {
    return id;
  }


  public void setId(Integer id) {
    this.id = id;
  }


  public Brand enabled(Boolean enabled) {
    
    this.enabled = enabled;
    return this;
  }

   /**
   * Indicates if the brand is enabled or not
   * @return enabled
  **/
  @javax.annotation.Nonnull
  public Boolean getEnabled() {
    return enabled;
  }


  public void setEnabled(Boolean enabled) {
    this.enabled = enabled;
  }


  public Brand customSupportEnabled(Boolean customSupportEnabled) {
    
    this.customSupportEnabled = customSupportEnabled;
    return this;
  }

   /**
   * Indicates if the custom support is enabled. If enabled, the login page includes the ability to submit a support request.
   * @return customSupportEnabled
  **/
  @javax.annotation.Nonnull
  public Boolean getCustomSupportEnabled() {
    return customSupportEnabled;
  }


  public void setCustomSupportEnabled(Boolean customSupportEnabled) {
    this.customSupportEnabled = customSupportEnabled;
  }


  public Brand customColor(String customColor) {
    
    this.customColor = customColor;
    return this;
  }

   /**
   * Primary brand color
   * @return customColor
  **/
  @javax.annotation.Nonnull
  public String getCustomColor() {
    return customColor;
  }


  public void setCustomColor(String customColor) {
    this.customColor = customColor;
  }


  public Brand customAccentColor(String customAccentColor) {
    
    this.customAccentColor = customAccentColor;
    return this;
  }

   /**
   * Secondary brand color
   * @return customAccentColor
  **/
  @javax.annotation.Nonnull
  public String getCustomAccentColor() {
    return customAccentColor;
  }


  public void setCustomAccentColor(String customAccentColor) {
    this.customAccentColor = customAccentColor;
  }


  public Brand customMaskingColor(String customMaskingColor) {
    
    this.customMaskingColor = customMaskingColor;
    return this;
  }

   /**
   * Color for the masking layer above the background image of the branded login screen.
   * @return customMaskingColor
  **/
  @javax.annotation.Nonnull
  public String getCustomMaskingColor() {
    return customMaskingColor;
  }


  public void setCustomMaskingColor(String customMaskingColor) {
    this.customMaskingColor = customMaskingColor;
  }


  public Brand customMaskingOpacity(Integer customMaskingOpacity) {
    
    this.customMaskingOpacity = customMaskingOpacity;
    return this;
  }

   /**
   * Opacity for the custom_masking_color.
   * @return customMaskingOpacity
  **/
  @javax.annotation.Nonnull
  public Integer getCustomMaskingOpacity() {
    return customMaskingOpacity;
  }


  public void setCustomMaskingOpacity(Integer customMaskingOpacity) {
    this.customMaskingOpacity = customMaskingOpacity;
  }


  public Brand mfaEnrollmentMessage(String mfaEnrollmentMessage) {
    
    this.mfaEnrollmentMessage = mfaEnrollmentMessage;
    return this;
  }

   /**
   * Text that replaces the default text displayed on the initial screen of the MFA Registration.
   * @return mfaEnrollmentMessage
  **/
  @javax.annotation.Nonnull
  public String getMfaEnrollmentMessage() {
    return mfaEnrollmentMessage;
  }


  public void setMfaEnrollmentMessage(String mfaEnrollmentMessage) {
    this.mfaEnrollmentMessage = mfaEnrollmentMessage;
  }


  public Brand enableCustomLabelForLoginScreen(Boolean enableCustomLabelForLoginScreen) {
    
    this.enableCustomLabelForLoginScreen = enableCustomLabelForLoginScreen;
    return this;
  }

   /**
   * Indicates if the custom Username/Email field label is enabled or not
   * @return enableCustomLabelForLoginScreen
  **/
  @javax.annotation.Nonnull
  public Boolean getEnableCustomLabelForLoginScreen() {
    return enableCustomLabelForLoginScreen;
  }


  public void setEnableCustomLabelForLoginScreen(Boolean enableCustomLabelForLoginScreen) {
    this.enableCustomLabelForLoginScreen = enableCustomLabelForLoginScreen;
  }


  public Brand customLabelTextForLoginScreen(String customLabelTextForLoginScreen) {
    
    this.customLabelTextForLoginScreen = customLabelTextForLoginScreen;
    return this;
  }

   /**
   * Custom label for the Username/Email field on the login screen. See example here.
   * @return customLabelTextForLoginScreen
  **/
  @javax.annotation.Nonnull
  public String getCustomLabelTextForLoginScreen() {
    return customLabelTextForLoginScreen;
  }


  public void setCustomLabelTextForLoginScreen(String customLabelTextForLoginScreen) {
    this.customLabelTextForLoginScreen = customLabelTextForLoginScreen;
  }


  public Brand loginInstruction(String loginInstruction) {
    
    this.loginInstruction = loginInstruction;
    return this;
  }

   /**
   * Text for the login instruction screen, styled in Markdown.
   * @return loginInstruction
  **/
  @javax.annotation.Nonnull
  public String getLoginInstruction() {
    return loginInstruction;
  }


  public void setLoginInstruction(String loginInstruction) {
    this.loginInstruction = loginInstruction;
  }


  public Brand loginInstructionTitle(String loginInstructionTitle) {
    
    this.loginInstructionTitle = loginInstructionTitle;
    return this;
  }

   /**
   * Link text to show login instruction screen.
   * @return loginInstructionTitle
  **/
  @javax.annotation.Nonnull
  public String getLoginInstructionTitle() {
    return loginInstructionTitle;
  }


  public void setLoginInstructionTitle(String loginInstructionTitle) {
    this.loginInstructionTitle = loginInstructionTitle;
  }


  public Brand hideOneloginFooter(Boolean hideOneloginFooter) {
    
    this.hideOneloginFooter = hideOneloginFooter;
    return this;
  }

   /**
   * Indicates if the OneLogin footer will appear at the bottom of the login page.
   * @return hideOneloginFooter
  **/
  @javax.annotation.Nonnull
  public Boolean getHideOneloginFooter() {
    return hideOneloginFooter;
  }


  public void setHideOneloginFooter(Boolean hideOneloginFooter) {
    this.hideOneloginFooter = hideOneloginFooter;
  }


  public Brand background(BrandBackground background) {
    
    this.background = background;
    return this;
  }

   /**
   * Get background
   * @return background
  **/
  @javax.annotation.Nonnull
  public BrandBackground getBackground() {
    return background;
  }


  public void setBackground(BrandBackground background) {
    this.background = background;
  }


  public Brand logo(BrandLogo logo) {
    
    this.logo = logo;
    return this;
  }

   /**
   * Get logo
   * @return logo
  **/
  @javax.annotation.Nonnull
  public BrandLogo getLogo() {
    return logo;
  }


  public void setLogo(BrandLogo logo) {
    this.logo = logo;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Brand brand = (Brand) o;
    return Objects.equals(this.id, brand.id) &&
        Objects.equals(this.enabled, brand.enabled) &&
        Objects.equals(this.customSupportEnabled, brand.customSupportEnabled) &&
        Objects.equals(this.customColor, brand.customColor) &&
        Objects.equals(this.customAccentColor, brand.customAccentColor) &&
        Objects.equals(this.customMaskingColor, brand.customMaskingColor) &&
        Objects.equals(this.customMaskingOpacity, brand.customMaskingOpacity) &&
        Objects.equals(this.mfaEnrollmentMessage, brand.mfaEnrollmentMessage) &&
        Objects.equals(this.enableCustomLabelForLoginScreen, brand.enableCustomLabelForLoginScreen) &&
        Objects.equals(this.customLabelTextForLoginScreen, brand.customLabelTextForLoginScreen) &&
        Objects.equals(this.loginInstruction, brand.loginInstruction) &&
        Objects.equals(this.loginInstructionTitle, brand.loginInstructionTitle) &&
        Objects.equals(this.hideOneloginFooter, brand.hideOneloginFooter) &&
        Objects.equals(this.background, brand.background) &&
        Objects.equals(this.logo, brand.logo);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, enabled, customSupportEnabled, customColor, customAccentColor, customMaskingColor, customMaskingOpacity, mfaEnrollmentMessage, enableCustomLabelForLoginScreen, customLabelTextForLoginScreen, loginInstruction, loginInstructionTitle, hideOneloginFooter, background, logo);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Brand {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    enabled: ").append(toIndentedString(enabled)).append("\n");
    sb.append("    customSupportEnabled: ").append(toIndentedString(customSupportEnabled)).append("\n");
    sb.append("    customColor: ").append(toIndentedString(customColor)).append("\n");
    sb.append("    customAccentColor: ").append(toIndentedString(customAccentColor)).append("\n");
    sb.append("    customMaskingColor: ").append(toIndentedString(customMaskingColor)).append("\n");
    sb.append("    customMaskingOpacity: ").append(toIndentedString(customMaskingOpacity)).append("\n");
    sb.append("    mfaEnrollmentMessage: ").append(toIndentedString(mfaEnrollmentMessage)).append("\n");
    sb.append("    enableCustomLabelForLoginScreen: ").append(toIndentedString(enableCustomLabelForLoginScreen)).append("\n");
    sb.append("    customLabelTextForLoginScreen: ").append(toIndentedString(customLabelTextForLoginScreen)).append("\n");
    sb.append("    loginInstruction: ").append(toIndentedString(loginInstruction)).append("\n");
    sb.append("    loginInstructionTitle: ").append(toIndentedString(loginInstructionTitle)).append("\n");
    sb.append("    hideOneloginFooter: ").append(toIndentedString(hideOneloginFooter)).append("\n");
    sb.append("    background: ").append(toIndentedString(background)).append("\n");
    sb.append("    logo: ").append(toIndentedString(logo)).append("\n");
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
    openapiFields.add("enabled");
    openapiFields.add("custom_support_enabled");
    openapiFields.add("custom_color");
    openapiFields.add("custom_accent_color");
    openapiFields.add("custom_masking_color");
    openapiFields.add("custom_masking_opacity");
    openapiFields.add("mfa_enrollment_message");
    openapiFields.add("enable_custom_label_for_login_screen");
    openapiFields.add("custom_label_text_for_login_screen");
    openapiFields.add("login_instruction");
    openapiFields.add("login_instruction_title");
    openapiFields.add("hide_onelogin_footer");
    openapiFields.add("background");
    openapiFields.add("logo");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
    openapiRequiredFields.add("id");
    openapiRequiredFields.add("enabled");
    openapiRequiredFields.add("custom_support_enabled");
    openapiRequiredFields.add("custom_color");
    openapiRequiredFields.add("custom_accent_color");
    openapiRequiredFields.add("custom_masking_color");
    openapiRequiredFields.add("custom_masking_opacity");
    openapiRequiredFields.add("mfa_enrollment_message");
    openapiRequiredFields.add("enable_custom_label_for_login_screen");
    openapiRequiredFields.add("custom_label_text_for_login_screen");
    openapiRequiredFields.add("login_instruction");
    openapiRequiredFields.add("login_instruction_title");
    openapiRequiredFields.add("hide_onelogin_footer");
    openapiRequiredFields.add("background");
    openapiRequiredFields.add("logo");
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to Brand
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (!Brand.openapiRequiredFields.isEmpty()) { // has required fields but JSON object is null
          throw new IllegalArgumentException(String.format("The required field(s) %s in Brand is not found in the empty JSON string", Brand.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!Brand.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `Brand` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }

      // check to make sure all required properties/fields are present in the JSON string
      for (String requiredField : Brand.openapiRequiredFields) {
        if (jsonObj.get(requiredField) == null) {
          throw new IllegalArgumentException(String.format("The required field `%s` is not found in the JSON string: %s", requiredField, jsonObj.toString()));
        }
      }
      if (!jsonObj.get("custom_color").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `custom_color` to be a primitive type in the JSON string but got `%s`", jsonObj.get("custom_color").toString()));
      }
      if (!jsonObj.get("custom_accent_color").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `custom_accent_color` to be a primitive type in the JSON string but got `%s`", jsonObj.get("custom_accent_color").toString()));
      }
      if (!jsonObj.get("custom_masking_color").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `custom_masking_color` to be a primitive type in the JSON string but got `%s`", jsonObj.get("custom_masking_color").toString()));
      }
      if (!jsonObj.get("mfa_enrollment_message").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `mfa_enrollment_message` to be a primitive type in the JSON string but got `%s`", jsonObj.get("mfa_enrollment_message").toString()));
      }
      if (!jsonObj.get("custom_label_text_for_login_screen").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `custom_label_text_for_login_screen` to be a primitive type in the JSON string but got `%s`", jsonObj.get("custom_label_text_for_login_screen").toString()));
      }
      if (!jsonObj.get("login_instruction").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `login_instruction` to be a primitive type in the JSON string but got `%s`", jsonObj.get("login_instruction").toString()));
      }
      if (!jsonObj.get("login_instruction_title").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `login_instruction_title` to be a primitive type in the JSON string but got `%s`", jsonObj.get("login_instruction_title").toString()));
      }
      // validate the required field `background`
      BrandBackground.validateJsonObject(jsonObj.getAsJsonObject("background"));
      // validate the required field `logo`
      BrandLogo.validateJsonObject(jsonObj.getAsJsonObject("logo"));
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!Brand.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'Brand' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<Brand> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(Brand.class));

       return (TypeAdapter<T>) new TypeAdapter<Brand>() {
           @Override
           public void write(JsonWriter out, Brand value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public Brand read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of Brand given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of Brand
  * @throws IOException if the JSON string is invalid with respect to Brand
  */
  public static Brand fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, Brand.class);
  }

 /**
  * Convert an instance of Brand to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

