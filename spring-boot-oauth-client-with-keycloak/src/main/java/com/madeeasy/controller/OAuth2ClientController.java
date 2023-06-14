package com.madeeasy.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

@RestController
public class OAuth2ClientController {

    private final RestTemplate restTemplate;
    private final OAuth2AuthorizedClientService authorizationService;

    public OAuth2ClientController(RestTemplate restTemplate, OAuth2AuthorizedClientService authorizationService) {
        this.restTemplate = restTemplate;
        this.authorizationService = authorizationService;
    }

    @GetMapping("/")
    public String index(@AuthenticationPrincipal OAuth2User principal,
                        OAuth2AuthenticationToken authenticationToken) {
        OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authenticationToken);
        System.out.println(authorizedClient.getAccessToken().getTokenValue());
        String accessToken = authorizedClient.getAccessToken().getTokenValue();

        /**
         *  think why we are sending access tokens to the resource server ?? as remember the situation when you
         *  use postman then you send access tokens to the resource server i.e.
         *  #1) GET http://localhost:8081/test/admin
         *  #2) Authorization > Bearer Token > Token : <Access_Token>
         */
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        // Add any other headers if needed

        RequestEntity<?> requestEntity = new RequestEntity<>(headers, HttpMethod.GET, URI.create("http://localhost:8081/test/admin"));
        ResponseEntity<String> responseEntity = restTemplate.exchange(requestEntity, String.class);

        return "Hello from resourceServer " + responseEntity.getBody();
    }

    private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken authenticationToken) {
        return this.authorizationService.loadAuthorizedClient(authenticationToken.getAuthorizedClientRegistrationId(),
                authenticationToken.getName());
    }

    @GetMapping("/hello")
    public String hello() {
        return "Hello World again";
    }
}
