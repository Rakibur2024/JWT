package com.jwt.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthenticationResponse {

    @JsonProperty("access_token")
    private String accesstoken;

    @JsonProperty("refresh_token")
    private String refreshtoken;

    public AuthenticationResponse(String accesstoken, String refreshtoken) {
        this.accesstoken = accesstoken;
        this.refreshtoken = refreshtoken;
    }

    public String getAccesstoken() {
        return accesstoken;
    }

    public String getRefreshtoken() {
        return refreshtoken;
    }
}
