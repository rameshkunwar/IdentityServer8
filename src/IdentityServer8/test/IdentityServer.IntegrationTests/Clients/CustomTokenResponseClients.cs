/*
 Copyright (c) 2024 HigginsSoft, Alexander Higgins - https://github.com/alexhiggins732/ 

 Copyright (c) 2018, Brock Allen & Dominick Baier. All rights reserved.

 Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information. 
 Source code and license this software can be found 

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
*/

using System.Buffers.Text;
using FluentAssertions;
using Duende.IdentityModel;
using Duende.IdentityModel.Client;
using IdentityServer.IntegrationTests.Clients.Setup;
using IdentityServer8.Extensions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text;
using System.Text.Json;
using Xunit;
using JsonSerializer = System.Text.Json.JsonSerializer;

namespace IdentityServer.IntegrationTests.Clients;

public class CustomTokenResponseClients
{
    private const string TokenEndpoint = "https://server/connect/token";

    private readonly HttpClient _client;

    public CustomTokenResponseClients()
    {
        var builder = new WebHostBuilder()
            .UseStartup<StartupWithCustomTokenResponses>();
        var server = new TestServer(builder);

        _client = server.CreateClient();
    }

    [Fact]
    public async Task Resource_owner_success_should_return_custom_response()
    {
        var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
        {
            Address = TokenEndpoint,
            ClientId = "roclient",
            ClientSecret = "secret",

            UserName = "bob",
            Password = "bob",
            Scope = "api1"
        });

        // raw fields
        var fields = GetFields(response);
        fields["string_value"].GetString().Should().Be("some_string");
        fields["int_value"].GetInt64().Should().Be(42);

        JsonElement temp;
        fields.TryGetValue("identity_token", out temp).Should().BeFalse();
        fields.TryGetValue("refresh_token", out temp).Should().BeFalse();
        fields.TryGetValue("error", out temp).Should().BeFalse();
        fields.TryGetValue("error_description", out temp).Should().BeFalse();
        fields.TryGetValue("token_type", out temp).Should().BeTrue();
        fields.TryGetValue("expires_in", out temp).Should().BeTrue();

        var responseObject = fields["dto"];
        responseObject.Should().NotBeNull();

        var responseDto = GetDto(responseObject);
        var dto = CustomResponseDto.Create;

        responseDto.string_value.Should().Be(dto.string_value);
        responseDto.int_value.Should().Be(dto.int_value);
        responseDto.nested.string_value.Should().Be(dto.nested.string_value);
        responseDto.nested.int_value.Should().Be(dto.nested.int_value);


        // token client response
        response.IsError.Should().Be(false);
        response.ExpiresIn.Should().Be(3600);
        response.TokenType.Should().Be("Bearer");
        response.IdentityToken.Should().BeNull();
        response.RefreshToken.Should().BeNull();


        // token content
        var payload = GetPayload(response);
        payload.Count().Should().Be(12);
        payload.Should().Contain("iss", "https://idsvr8");
        payload.Should().Contain("client_id", "roclient");
        payload.Should().Contain("sub", "bob");
        payload.Should().Contain("idp", "local");

        payload["aud"].Should().Be("api");

        var scopes = payload["scope"] as JArray;
        scopes.First().ToString().Should().Be("api1");

        var amr = payload["amr"] as JArray;
        amr.Count().Should().Be(1);
        amr.First().ToString().Should().Be("password");
    }

    [Fact]
    public async Task Resource_owner_failure_should_return_custom_error_response()
    {
        var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
        {
            Address = TokenEndpoint,
            ClientId = "roclient",
            ClientSecret = "secret",

            UserName = "bob",
            Password = "invalid",
            Scope = "api1"
        });

        // raw fields
        var fields = GetFields(response);
        fields["string_value"].ToString().Should().Be("some_string");
        fields["int_value"].GetInt64().Should().Be(42);

        JsonElement temp;
        fields.TryGetValue("identity_token", out temp).Should().BeFalse();
        fields.TryGetValue("refresh_token", out temp).Should().BeFalse();
        fields.TryGetValue("error", out temp).Should().BeTrue();
        fields.TryGetValue("error_description", out temp).Should().BeTrue();
        fields.TryGetValue("token_type", out temp).Should().BeFalse();
        fields.TryGetValue("expires_in", out temp).Should().BeFalse();

        var responseObject = fields["dto"];
        responseObject.Should().NotBeNull();

        var responseDto = GetDto(responseObject);
        var dto = CustomResponseDto.Create;

        responseDto.string_value.Should().Be(dto.string_value);
        responseDto.int_value.Should().Be(dto.int_value);
        responseDto.nested.string_value.Should().Be(dto.nested.string_value);
        responseDto.nested.int_value.Should().Be(dto.nested.int_value);


        // token client response
        response.IsError.Should().Be(true);
        response.Error.Should().Be("invalid_grant");
        response.ErrorDescription.Should().Be("invalid_credential");
        response.ExpiresIn.Should().Be(0);
        response.TokenType.Should().BeNull();
        response.IdentityToken.Should().BeNull();
        response.RefreshToken.Should().BeNull();
    }

    [Fact]
    public async Task Extension_grant_success_should_return_custom_response()
    {
        var response = await _client.RequestTokenAsync(new TokenRequest
        {
            Address = TokenEndpoint,
            GrantType = "custom",

            ClientId = "client.custom",
            ClientSecret = "secret",

            Parameters =
            {
                { "scope", "api1" },
                { "outcome", "succeed"}
            }
        });


        // raw fields
        var fields = GetFields(response);
        fields["string_value"].ToString().Should().Be("some_string");
        fields["int_value"].GetInt64().Should().Be(42);

        JsonElement temp;
        fields.TryGetValue("identity_token", out temp).Should().BeFalse();
        fields.TryGetValue("refresh_token", out temp).Should().BeFalse();
        fields.TryGetValue("error", out temp).Should().BeFalse();
        fields.TryGetValue("error_description", out temp).Should().BeFalse();
        fields.TryGetValue("token_type", out temp).Should().BeTrue();
        fields.TryGetValue("expires_in", out temp).Should().BeTrue();

        var responseObject = fields["dto"];
        responseObject.Should().NotBeNull();

        var responseDto = GetDto(responseObject);
        var dto = CustomResponseDto.Create;

        responseDto.string_value.Should().Be(dto.string_value);
        responseDto.int_value.Should().Be(dto.int_value);
        responseDto.nested.string_value.Should().Be(dto.nested.string_value);
        responseDto.nested.int_value.Should().Be(dto.nested.int_value);


        // token client response
        response.IsError.Should().Be(false);
        response.ExpiresIn.Should().Be(3600);
        response.TokenType.Should().Be("Bearer");
        response.IdentityToken.Should().BeNull();
        response.RefreshToken.Should().BeNull();


        // token content
        var payload = GetPayload(response);
        payload.Count().Should().Be(12);
        payload.Should().Contain("iss", "https://idsvr8");
        payload.Should().Contain("client_id", "client.custom");
        payload.Should().Contain("sub", "bob");
        payload.Should().Contain("idp", "local");

        payload["aud"].Should().Be("api");

        var scopes = payload["scope"] as JArray;
        scopes.First().ToString().Should().Be("api1");

        var amr = payload["amr"] as JArray;
        amr.Count().Should().Be(1);
        amr.First().ToString().Should().Be("custom");

    }

    [Fact]
    public async Task Extension_grant_failure_should_return_custom_error_response()
    {
        var response = await _client.RequestTokenAsync(new TokenRequest
        {
            Address = TokenEndpoint,
            GrantType = "custom",

            ClientId = "client.custom",
            ClientSecret = "secret",

            Parameters =
            {
                { "scope", "api1" },
                { "outcome", "fail"}
            }
        });

        var s = response.Json.ToString();
        var fd = GetFieldsD(response);
        // raw fields
        var fields = GetFields(response);
        fields["string_value"].ToString().Should().Be("some_string");
        fields["int_value"].GetInt64().Should().Be(42);

        JsonElement temp;
        fields.TryGetValue("identity_token", out temp).Should().BeFalse();
        fields.TryGetValue("refresh_token", out temp).Should().BeFalse();
        fields.TryGetValue("error", out temp).Should().BeTrue();
        fields.TryGetValue("error_description", out temp).Should().BeTrue();
        fields.TryGetValue("token_type", out temp).Should().BeFalse();
        fields.TryGetValue("expires_in", out temp).Should().BeFalse();

        var responseObject = fields["dto"];
        responseObject.Should().NotBeNull();

        var responseDto = GetDto(responseObject);
        var dto = CustomResponseDto.Create;

        responseDto.string_value.Should().Be(dto.string_value);
        responseDto.int_value.Should().Be(dto.int_value);
        responseDto.nested.string_value.Should().Be(dto.nested.string_value);
        responseDto.nested.int_value.Should().Be(dto.nested.int_value);


        // token client response
        response.IsError.Should().Be(true);
        response.Error.Should().Be("invalid_grant");
        response.ErrorDescription.Should().Be("invalid_credential");
        response.ExpiresIn.Should().Be(0);
        response.TokenType.Should().BeNull();
        response.IdentityToken.Should().BeNull();
        response.RefreshToken.Should().BeNull();
    }

    private CustomResponseDto GetDto(JsonElement responseObject)
    {
        return responseObject.ToObject<CustomResponseDto>();
    }

    // private Dictionary<string, object> GetFieldsD(TokenResponse response)
    // {
    //     return response.Json.ToObject<Dictionary<string, object>>();
    // }


    // private Dictionary<string, JsonElement> GetFields(TokenResponse response)
    // {
    //     return GetFields(response.Json);
    // }
    //
    // private Dictionary<string, JsonElement> GetFields(JsonElement json)
    // {
    //     return json.ToObject<Dictionary<string, JsonElement>>();
    // }
    private Dictionary<string, object> GetFieldsD(TokenResponse response)
    {
        // Use the raw response if Json is null/empty
        if (!response.Json.HasValue)
        {
            using var doc = JsonDocument.Parse(response.Raw ?? "{}");
            return ExtractValues(doc.RootElement);
        }

        return ExtractValues(response.Json.Value);
    }

    private Dictionary<string, object> ExtractValues(JsonElement element)
    {
        var dictionary = new Dictionary<string, object>();
    
        foreach (var property in element.EnumerateObject())
        {
            dictionary.Add(property.Name, ConvertElement(property.Value));
        }
    
        return dictionary;
    }

    private object ConvertElement(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString()!,
            JsonValueKind.Number => element.TryGetInt64(out var l) ? l : element.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null!,
            JsonValueKind.Object => ExtractValues(element),
            JsonValueKind.Array => element.EnumerateArray().Select(ConvertElement).ToList(),
            _ => element.GetRawText()
        };
    }
    private Dictionary<string, JsonElement> GetFields(TokenResponse response)
    {
        // Check if Json is present; if not, parse the Raw string
        if (response.Json.HasValue)
        {
            return GetFields(response.Json.Value);
        }
    
        // Fallback: Parse the raw string if the Json property is empty
        using var doc = JsonDocument.Parse(response.Raw ?? "{}");
        return GetFields(doc.RootElement);
    }

    private Dictionary<string, JsonElement> GetFields(JsonElement json)
    {
        // Replacement for .ToObject<T>()
        return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json.GetRawText()) 
               ?? new Dictionary<string, JsonElement>();
    }

    private Dictionary<string, object> GetPayload(TokenResponse response)
    {
        var token = response.AccessToken.Split('.').Skip(1).Take(1).First();
        var dictionary = JsonConvert.DeserializeObject<Dictionary<string, object>>(
            Encoding.UTF8.GetString(Base64Url.DecodeFromChars(token)));

        return dictionary;
    }
}
