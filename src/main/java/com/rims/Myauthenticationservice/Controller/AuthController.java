package com.rims.Myauthenticationservice.Controller;

import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletResponse;

import com.rims.Myauthenticationservice.Security.JwtService;
import com.rims.Myauthenticationservice.dto.AuthRequest;

//import io.micrometer.core.ipc.http.HttpSender.Response;


@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final UserDetailsService uds;

    public AuthController(AuthenticationManager authManager, JwtService jwtService, UserDetailsService uds) {
        this.authManager = authManager;
        this.jwtService = jwtService;
        this.uds = uds;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request,HttpServletResponse response) {
        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
            System.out.println("In login section");
            UserDetails userDetails = uds.loadUserByUsername(request.getUsername());
            String token = jwtService.generateToken(userDetails);
            String refreshToken = jwtService.generateRefreshToken(userDetails);
            //It tells the browser to store a cookie named refreshToken also delete the cookie from browser when time comes and send the cookie to a spcific api when request matches
            ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)          //browser protect from xss as JS cannot read → XSS protection
                .secure(false)              // BroswerOnly over HTTPS
                .sameSite("Lax")        // Browser protect cookie from CSRF protection as Strict prevents the cookie from being sent on cross-site requests
                .path("/auth/refresh")     // Cookie is sent  by browseronly when /auth/refresh is called not any other APIs and browser handles automatically
                .maxAge(10*60) //browser will remove the refresh token from cookie aftre this time
                .build();

                response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

            // return token and basic user info
            return ResponseEntity.ok(Map.of(
                    "token", token,
                    "username", userDetails.getUsername()
                    
            ));
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }
    }
   @PostMapping("/refresh")
public ResponseEntity<?> refresh(
    @CookieValue(value = "refreshToken", required = false) String refreshToken) {
        System.out.println();
        System.out.println("**********************************************************************");
		System.out.println("Refresh Token - "+refreshToken);
		System.out.println("**********************************************************************");
        System.out.println();
        
    if (refreshToken == null) {
        return ResponseEntity.status(401).body(Map.of(
            "error", "Refresh token missing"
        ));
    }

    try {
        String username = jwtService.extractUsername(refreshToken);
        UserDetails userDetails = uds.loadUserByUsername(username);

        if (jwtService.isTRefreshokenValid(refreshToken, userDetails)) {
            String token = jwtService.generateToken(userDetails);
            return ResponseEntity.ok(Map.of(
                "token", token,
                "username", userDetails.getUsername()
            ));
        }
        else{
            System.out.println("\n"+"Refresh token is expired"+"\n");
            return ResponseEntity.status(401).body(Map.of(
        "error", "Invalid or expired refresh token"
        
    )); 
        }
    } catch (Exception e) {
        // token invalid / expired / tampered
        System.out.println();
        System.out.println("**********************************************************************");
		System.out.println(e);
		System.out.println("**********************************************************************");
        System.out.println();
        
    }

    return ResponseEntity.status(401).body(Map.of(
        "error", "Invalid or expired refresh token"
    ));
}
}




