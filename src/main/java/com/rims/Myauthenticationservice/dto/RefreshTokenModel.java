package com.rims.Myauthenticationservice.dto;

import jakarta.persistence.Column;

public class RefreshTokenModel {
    
    private Long Id;

    private String rToken;

    private Boolean isExpired;

    public Long getId() {
        return Id;
    }

    public void setId(Long id) {
        Id = id;
    }

    public String getrToken() {
        return rToken;
    }

    public void setrToken(String rToken) {
        this.rToken = rToken;
    }

    public Boolean getIsExpired() {
        return isExpired;
    }

    public void setIsExpired(Boolean isExpired) {
        this.isExpired = isExpired;
    }

    
}
