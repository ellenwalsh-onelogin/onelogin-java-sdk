package com.onelogin.sdk.model;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

public class SessionTokenMFAInfo extends SessionToken {

    public String stateToken;
	public String callbackUrl;
	public List<Device> devices = new ArrayList<Device>(); 

	public SessionTokenMFAInfo(JSONObject data) {
		user = new User(data.getJSONObject("user"));
		stateToken = data.optString("state_token", null);
		callbackUrl = data.optString("callback_url", null);
		
		JSONArray dataArray = data.getJSONArray("devices");
		for (int i = 0; i < dataArray.length(); i++) {
			JSONObject jobj = dataArray.getJSONObject(i);
			devices.add(new Device(jobj));
		}
	}

	public String getStateToken() {
		return stateToken;
	}

	public String getCallbackUrl()	{
		return callbackUrl;
	}

	public List<Device> getDevices()	{
		return devices;
	}
}
