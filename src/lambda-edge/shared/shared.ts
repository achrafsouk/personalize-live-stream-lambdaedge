// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { CloudFrontHeaders } from 'aws-lambda';
import { readFileSync } from 'fs';

export interface CookieSettings {
    idToken: string;
    accessToken: string;
    refreshToken: string;
    nonce: string;
}

export interface HttpHeaders {
    [key: string]: string;
}

interface ConfigFromDisk {
    userPoolId: string;
    clientId: string;
    oauthScopes: string[];
    cognitoAuthDomain: string;
    redirectPathSignIn: string;
    redirectPathSignOut: string;
    redirectPathAuthRefresh: string;
    cookieSettings: CookieSettings;
    httpHeaders: HttpHeaders;
}


export interface Config extends ConfigFromDisk {
    tokenIssuer: string;
    tokenJwksUri: string;
    cloudFrontHeaders: CloudFrontHeaders;
}


export function getConfig(): Config {

    const config = JSON.parse(readFileSync(`${__dirname}/configuration.json`).toString('utf8')) as ConfigFromDisk;

    // Derive the issuer and JWKS uri all JWT's will be signed with from the User Pool's ID and region:
    const userPoolRegion = config.userPoolId.match(/(\S{2}-\S{4}-\S{1,2})_\S*/)![1];
    const tokenIssuer = `https://cognito-idp.${userPoolRegion}.amazonaws.com/${config.userPoolId}`;
    const tokenJwksUri = `${tokenIssuer}/.well-known/jwks.json`;

    return {
        ...config, tokenIssuer, tokenJwksUri, cloudFrontHeaders: asCloudFrontHeaders(config.httpHeaders)
    };
}

type Cookies = { [key: string]: string };

function extractCookiesFromHeaders(headers: CloudFrontHeaders) {
    // Cookies are present in the HTTP header "Cookie" that may be present multiple times. 
    // This utility function parses occurrences  of that header and splits out all the cookies and their values
    // A simple object is returned that allows easy access by cookie name: e.g. cookies["nonce"]
    if (!headers['cookie']) {
        return {};
    }
    const cookies = headers['cookie'].reduce((reduced, header) => {
        const cookies_ = header.value.split(';').reduce((reduced_, cookie) => {
            const [name, ...value] = cookie.split('=');
            return Object.assign(reduced_, { [name.trim()]: decodeURI(value.join('=')) });
        }, {} as Cookies);
        return Object.assign(reduced, cookies_);
    }, {} as Cookies);

    return cookies;
}

function withCookieDomain(distributionDomainName: string, cookieSettings: string) {
    if (cookieSettings.toLowerCase().indexOf('domain') === -1) {
        // Add leading dot for compatibility with Amplify (or js-cookie really)
        return `${cookieSettings}; Domain=.${distributionDomainName}`;
    }
    return cookieSettings;
}

export function asCloudFrontHeaders(headers: HttpHeaders): CloudFrontHeaders {
    return Object.entries(headers).reduce((reduced, [key, value]) => (
        Object.assign(reduced, {
            [key.toLowerCase()]: [{
                key,
                value
            }]
        })
    ), {} as CloudFrontHeaders);
}

export function extractAndParseCookies(headers: CloudFrontHeaders, clientId: string) {
    const cookies = extractCookiesFromHeaders(headers);
    if (!cookies) {
        return {};
    }

    const keyPrefix = `CognitoIdentityServiceProvider.${clientId}`;
    const lastUserKey = `${keyPrefix}.LastAuthUser`;
    const tokenUserName = cookies[lastUserKey];

    const scopeKey = `${keyPrefix}.${tokenUserName}.tokenScopesString`;
    const scopes = cookies[scopeKey];

    const idTokenKey = `${keyPrefix}.${tokenUserName}.idToken`;
    const idToken = cookies[idTokenKey];

    const accessTokenKey = `${keyPrefix}.${tokenUserName}.accessToken`;
    const accessToken = cookies[accessTokenKey];

    const refreshTokenKey = `${keyPrefix}.${tokenUserName}.refreshToken`;
    const refreshToken = cookies[refreshTokenKey];

    return {
        tokenUserName,
        idToken,
        accessToken,
        refreshToken,
        scopes,
        nonce: cookies['spa-auth-edge-nonce'],
        pkce: cookies['spa-auth-edge-pkce'],
    }
}

export function decodeToken(jwt: string) {
    const tokenBody = jwt.split('.')[1];
    const decodableTokenBody = tokenBody.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(decodableTokenBody, 'base64').toString());
}

export function getCookieHeaders(
    clientId: string,
    oauthScopes: string[],
    tokens: { id_token: string, access_token: string, refresh_token?: string },
    domainName: string,
    cookieSettings: CookieSettings
) {
    // Set cookies with the exact names and values Amplify uses for seamless interoperability with Amplify
    const decodedIdToken = decodeToken(tokens.id_token);
    const tokenUserName = decodedIdToken['cognito:username'];
    const keyPrefix = `CognitoIdentityServiceProvider.${clientId}`;
    const idTokenKey = `${keyPrefix}.${tokenUserName}.idToken`;
    const accessTokenKey = `${keyPrefix}.${tokenUserName}.accessToken`;
    const refreshTokenKey = `${keyPrefix}.${tokenUserName}.refreshToken`;
    const lastUserKey = `${keyPrefix}.LastAuthUser`;
    const scopeKey = `${keyPrefix}.${tokenUserName}.tokenScopesString`;
    const scopesString = oauthScopes.join(' ');
    const expireRefreshToken = tokens.refresh_token ? '' : `; Expires=${new Date(0).toUTCString()}`;
    const userDataKey = `${keyPrefix}.${tokenUserName}.userData`;
    const userData = JSON.stringify({
        UserAttributes: [
            {
                Name: 'sub',
                Value: decodedIdToken['sub']
            },
            {
                Name: 'email',
                Value: decodedIdToken['email']
            }
        ],
        Username: tokenUserName
    });

    return [
        [idTokenKey, `${tokens.id_token}; ${withCookieDomain(domainName, cookieSettings.idToken)}`],
        [accessTokenKey, `${tokens.access_token}; ${withCookieDomain(domainName, cookieSettings.accessToken)}`],
        [refreshTokenKey, `${tokens.refresh_token}; ${withCookieDomain(domainName, cookieSettings.refreshToken)}${expireRefreshToken}`],
        [lastUserKey, `${tokenUserName}; ${withCookieDomain(domainName, cookieSettings.idToken)}`],
        [scopeKey, `${scopesString}; ${withCookieDomain(domainName, cookieSettings.accessToken)}`],
        ['amplify-signin-with-hostedUI', `true; ${withCookieDomain(domainName, cookieSettings.accessToken)}`],
        [userDataKey, `${encodeURIComponent(userData)}; ${withCookieDomain(domainName, cookieSettings.idToken)}`],
    ].map(([k, v]) => ({ key: 'set-cookie', value: `${k}=${v}` }));
}
