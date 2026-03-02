package com.rims.Myauthenticationservice.Entity;

import jakarta.persistence.*;

@Entity
@Table(name="refreshToken")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy=GenerationType.AUTO)
    private Long Id;

    @Column(name="rToken")
    private String rToken;

    @Column(name="expired")
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
