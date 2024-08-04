package dev.iratherfear.springsecurity;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class JwtController {
    
    @Autowired
    private JwtEncoder jwtEncoder;

    @PostMapping("/authenticate")
    public JwtResponse authenticate(Authentication authentication) {
        return new JwtResponse(createdToken(authentication));
    }

    private String createdToken(Authentication authentication) {
        var claims = JwtClaimsSet.builder()
                                .issuer("self")
                                .issuedAt(Instant.now())
                                .expiresAt(Instant.now().plusSeconds(30 * 60))
                                .subject(authentication.getName())
                                .claim("scope", createScope(authentication))
                                .build();
        JwtEncoderParameters parameters = JwtEncoderParameters.from(claims);
        return jwtEncoder.encode(parameters).getTokenValue();
    }

    private String createScope(Authentication authentication) {
        return authentication.getAuthorities().stream()
                        .map(a -> a.getAuthority())
                        .collect(Collectors.joining(" "));
    }               
    
}


record JwtResponse(String token) {}