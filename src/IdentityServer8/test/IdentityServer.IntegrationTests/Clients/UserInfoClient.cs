/*
 Copyright (c) 2024 HigginsSoft, Alexander Higgins - https://github.com/alexhiggins732/ 

 Copyright (c) 2018, Brock Allen & Dominick Baier. All rights reserved.

 Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information. 
 Source code and license this software can be found 

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
*/

using System.Buffers.Text;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using Duende.IdentityModel;
using Duende.IdentityModel.Client;
using IdentityServer.IntegrationTests.Clients.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;

namespace IdentityServer.IntegrationTests.Clients;

public class UserInfoEndpointClient
{
    private const string TokenEndpoint = "https://server/connect/token";
    private const string UserInfoEndpoint = "https://server/connect/userinfo";

    private readonly HttpClient _client;

    public UserInfoEndpointClient()
    {
        var builder = new WebHostBuilder()
            .UseStartup<Startup>();
        var server = new TestServer(builder);

        _client = server.CreateClient();
    }

    [Fact]
    public async Task Valid_client_with_GET_should_succeed()
    {
        var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
        {
            Address = TokenEndpoint,
            ClientId = "roclient",
            ClientSecret = "secret",

            Scope = "openid email api1",
            UserName = "bob",
            Password = "bob"
        });

        response.IsError.Should().BeFalse();

        var userInfo = await _client.GetUserInfoAsync(new UserInfoRequest
        {
            Address = UserInfoEndpoint,
            Token = response.AccessToken
        });

        userInfo.IsError.Should().BeFalse();
        userInfo.Claims.Count().Should().Be(3);

        userInfo.Claims.Should().Contain(c => c.Type == "sub" && c.Value == "88421113");
        userInfo.Claims.Should().Contain(c => c.Type == "email" && c.Value == "BobSmith@email.com");
        userInfo.Claims.Should().Contain(c => c.Type == "email_verified" && c.Value == "true");
    }

    [Fact]
    public async Task Request_address_scope_should_return_expected_response()
    {
        var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
        {
            Address = TokenEndpoint,
            ClientId = "roclient",
            ClientSecret = "secret",

            Scope = "openid address",
            UserName = "bob",
            Password = "bob"
        });

        response.IsError.Should().BeFalse();

        var userInfo = await _client.GetUserInfoAsync(new UserInfoRequest
        {
            Address = UserInfoEndpoint,
            Token = response.AccessToken
        });

        userInfo.IsError.Should().BeFalse();
        userInfo.Claims.First().Value.Should().Be("{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69118, 'country': 'Germany' }");
    }

    [Fact]
    public async Task Using_a_token_with_no_identity_scope_should_fail()
    {
        var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
        {
            Address = TokenEndpoint,
            ClientId = "roclient",
            ClientSecret = "secret",

            Scope = "api1",
            UserName = "bob",
            Password = "bob"
        });

        response.IsError.Should().BeFalse();

        var userInfo = await _client.GetUserInfoAsync(new UserInfoRequest
        {
            Address = UserInfoEndpoint,
            Token = response.AccessToken
        });

        userInfo.IsError.Should().BeTrue();
        userInfo.HttpStatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Using_a_token_with_an_identity_scope_but_no_openid_should_fail()
    {
        var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
        {
            Address = TokenEndpoint,
            ClientId = "roclient",
            ClientSecret = "secret",

            Scope = "email api1",
            UserName = "bob",
            Password = "bob"
        });

        response.IsError.Should().BeFalse();

        var userInfo = await _client.GetUserInfoAsync(new UserInfoRequest
        {
            Address = UserInfoEndpoint,
            Token = response.AccessToken
        });

        userInfo.IsError.Should().BeTrue();
        userInfo.HttpStatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Invalid_token_should_fail()
    {
        var userInfo = await _client.GetUserInfoAsync(new UserInfoRequest
        {
            Address = UserInfoEndpoint,
            Token = "invalid"
        });

        userInfo.IsError.Should().BeTrue();
        userInfo.HttpStatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Complex_json_should_be_correct()
{
    var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
    {
        Address = TokenEndpoint,
        ClientId = "roclient",
        ClientSecret = "secret",
        Scope = "openid email api1 api4.with.roles roles",
        UserName = "bob",
        Password = "bob"
    });

    response.IsError.Should().BeFalse();

    // 1. Get the payload as a JsonElement-backed dictionary
    var payload = GetPayload(response);

    // 2. Validate Scopes (Handling JsonElement array)
    var scopes = payload["scope"].EnumerateArray().Select(x => x.GetString()).ToArray();
    scopes.Length.Should().Be(5);
    scopes.Should().Contain(new[] { "openid", "email", "api1", "api4.with.roles", "roles" });

    // 3. Validate Roles
    var roles = payload["role"].EnumerateArray().Select(x => x.GetString()).ToArray();
    roles.Length.Should().Be(2);
    roles.Should().Contain(new[] { "Geek", "Developer" });

    var userInfo = await _client.GetUserInfoAsync(new UserInfoRequest
    {
        Address = UserInfoEndpoint,
        Token = response.AccessToken
    });

    // 4. Validate UserInfo Roles (System.Text.Json way)
    if (userInfo.Json.HasValue)
    {
        if (userInfo.Json.Value.TryGetProperty("role", out var roleProperty))
        {
            var userInfoRoles = roleProperty.EnumerateArray().Select(x => x.GetString()).ToArray();
            userInfoRoles.Length.Should().Be(2);
            userInfoRoles.Should().Contain("Geek");
            userInfoRoles.Should().Contain("Developer");
        }
        else
        {
            Assert.Fail("Role property missing from UserInfo");
        }
    }
    else
    {
        Assert.Fail("Role property missing from UserInfo");
    }
}

private Dictionary<string, JsonElement> GetPayload(TokenResponse response)
{
    // Use the optimized JsonWebToken class instead of manual string splitting
    var handler = new JsonWebTokenHandler();
    var jwt = handler.ReadJsonWebToken(response.AccessToken);

    // IdentityModel 8.x stores claims as a Dictionary<string, object> 
    // where 'object' is actually a JsonElement in most modern scenarios.
    // If your version returns a string, parse it:
    using var doc = JsonDocument.Parse(jwt.EncodedPayload);
    
    return doc.RootElement.EnumerateObject()
        .ToDictionary(p => p.Name, p => p.Value.Clone());
}
}
