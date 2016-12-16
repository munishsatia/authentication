- Token Generator
-- TokenProviderMiddleware (Startup.cs)
-- POST : http://localhost:5000/token
-- header : Content-Type / application/x-www-form-urlencoded
-- Body : username=TEST&password=TEST123

-- TokenAuthenticator (Startup.cs)
--- services.AddAuthorization(auth =>
            {
                auth.AddPolicy("Bearer", new AuthorizationPolicyBuilder()
                    .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme‌​)
                    .RequireAuthenticatedUser().Build());
            });
--- AuthenticationController
--- GET http://localhost:5000/api/Authentication
--- header : Authorization - Bearer [Token]

