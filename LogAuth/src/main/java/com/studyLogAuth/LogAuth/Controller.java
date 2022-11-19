/**
 * 
 */
package com.studyLogAuth.LogAuth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

/**
 * @author user
 *
 */
@RestController
public class Controller {

	
	@GetMapping(path="/api/study_auth")
	public String AuthApi(HttpServletRequest request) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		String token = request.getHeader("Authorization").split(" ")[1];
		
//		System.out.println(token);
		
		DecodedJWT jwt = validate(token);
		
		System.out.println(jwt.getAudience());
		System.out.println(jwt.getExpiresAt());
		
		return "true";	
	}
	
	
	private DecodedJWT validate(String token) {
		try {
			final DecodedJWT jwt = JWT.decode(token);
			
			byte[] keyBytes = Files.readAllBytes(Paths.get("public.pub"));

	        X509EncodedKeySpec spec =
	          new X509EncodedKeySpec(keyBytes);
	        KeyFactory kf = KeyFactory.getInstance("RSA");
	        RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(spec);
	        
	        Algorithm algorithm = Algorithm.RSA256(publicKey, null);
	     
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(jwt.getIssuer())
                    .build();

            verifier.verify(token);
            
            
            return jwt;
		
		} catch(Exception e) {
			throw new InvalidParameterException("JWT validation failed: " + e.getMessage());
		}
		
		
		
	}
}
