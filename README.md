# soteria-google-oauth-client

Soteria/JSR 375 authentication mechanism for OAuth using the Google client library.

## Configuring

The base authentication mechanism provided by this library (`org.omnifaces.soteria.mechanism.OAuthClientServerBaseModule`) has to be configured 
via 2 constructor parameters. The authentication mechanism can be activated in a JSR 375 environment by creating an enabled CDI bean implementing the
`HttpAuthenticationMechanism` interface.

This enabled bean can either inherit from the provided `OAuthClientServerBaseModule` or delegate to it. The code below shows an example using
inheritance. Note that the `@Inject @Setting` is fictional and just refers to any way to obtain the required parameters.

See the documentation of `com.google.api.client.auth.oauth2.AuthorizationCodeFlow` for further details.

**This library is experimental and currently only suitable for demonstration purposes!**


```
@ApplicationScoped
@AutoApplySession
@RememberMe
@LoginToContinue(
    loginPage="/some_login_page.xhtml"
)
public class OAuthClientAuthenticationMechanism extends OAuthClientServerBaseModule implements HttpAuthenticationMechanism {
    
    @Inject
    @Setting
    private String authorizationServerURL;

    @Inject
    @Setting
    private String tokenServerURL;

    @Inject
    @Setting
    private String apiClientId;

    @Inject
    @Setting
    private String apiClientSecret;
    
    @PostConstruct
    public void init() {
        super.init(getOptions(), getFlow());
    }
    
    private static Map<String, String> getOptions() {
        Map<String, String> oauthClientOptions = new HashMap<>();
        oauthClientOptions.put(CALLBACK_URL, "/some_login_page.xhtml");
        oauthClientOptions.put(REGISTRATION_ERROR_URL, "/some_login_page.xhtml");
        oauthClientOptions.put(PUBLIC_REDIRECT_URL, "/some_login_page.xhtml");
        
        return oauthClientOptions;
    }
    
    private AuthorizationCodeFlow getFlow() {
        return new AuthorizationCodeFlow.Builder(BearerToken.authorizationHeaderAccessMethod(),
                new NetHttpTransport(), new JacksonFactory(), new GenericUrl(tokenServerURL),
                new ClientParametersAuthentication(apiClientId, apiClientSecret), apiClientId, authorizationServerURL).build();
    }

}
```



