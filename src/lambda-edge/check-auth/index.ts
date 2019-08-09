// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { stringify as stringifyQueryString } from 'querystring';
import { CloudFrontRequestHandler } from 'aws-lambda';
import { validate } from './validate-jwt';
import { getConfig, extractAndParseCookies, decodeToken } from '../shared/shared';
import { randomBytes, createHash } from 'crypto';

import { get, Agent } from 'https'; 

//https://github.com/NaturalIntelligence/fast-xml-parser
import {parse} from 'fast-xml-parser';
var Parser = require("fast-xml-parser").j2xParser;
var he = require('he');

export interface HttpResponse {
    code: Number;
    bodyBuffer: Buffer;
}
//const crypto = require('crypto');
//var fs = require("fs");

//const cfKeypairId = 'APKAJZBXYQEB3DUORKDA'; 
//const privateKey = fs.readFileSync("key.pem");

const keepAliveAgentOrigin = new Agent({ keepAlive: true, keepAliveMsecs: 1000});
const DEFAULT_HTTP_REQUEST_TIMEOUT = 2000;

const { clientId, oauthScopes, cognitoAuthDomain, redirectPathSignIn, redirectPathAuthRefresh,
    tokenIssuer, tokenJwksUri, cookieSettings, cloudFrontHeaders } = getConfig();

const redirectPathSignOut = '/console/index.html';

const unavailableManifest = 
    `<?xml version="1.0" encoding="UTF-8"?>
    <MPD xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="urn:mpeg:dash:schema:mpd:2011" xmlns:cenc="urn:mpeg:cenc:2013" xsi:schemaLocation="urn:mpeg:dash:schema:mpd:2011 http://standards.iso.org/ittf/PubliclyAvailableStandards/MPEG-DASH_schema_files/DASH-MPD.xsd" type="static" minBufferTime="PT12S" profiles="urn:mpeg:dash:profile:isoff-main:2011" mediaPresentationDuration="PT20.987S">
      <Period start="PT0S" duration="PT20.987S" id="1">
        <AdaptationSet mimeType="video/mp4" codecs="avc1.4d4028,mp4a.40.2" frameRate="30000/1001" segmentAlignment="true" subsegmentAlignment="true" startWithSAP="1" subsegmentStartsWithSAP="1" bitstreamSwitching="false">
          <ContentComponent contentType="video" id="1"/>
          <SegmentTemplate timescale="90000" media="https://CLOUDFRONT_DOMAIN/unavailable/unavailable_$Number%09d$.mp4" initialization="https://CLOUDFRONT_DOMAIN/unavailable/unavailableinit.mp4" duration="1081080" startNumber="1"/>
          <Representation id="1" width="1920" height="1080" bandwidth="1000000">
            <SubRepresentation contentComponent="1" bandwidth="1000000" codecs="avc1.4d4028"/>
          </Representation>
        </AdaptationSet>
      </Period>
    </MPD>`;


export const handler: CloudFrontRequestHandler = async (event) => {
    const request = event.Records[0].cf.request;
    const domainName = request.headers['host'][0].value;
    const requestedUri = `${request.uri}${request.querystring ? '?' + request.querystring : ''}`;
    console.log(`requestedUri = ${requestedUri}`);
    const nonce = randomBytes(10).toString('hex');
    try {
        if ((!request.origin) || (!request.origin.custom))
            throw new Error('Mediapackage domain is not defined');
        const mediapackageDomain = request.origin.custom.domainName;
        const { tokenUserName, idToken, refreshToken } = extractAndParseCookies(request.headers, clientId);
        if (!tokenUserName || !idToken) {
            throw new Error('No valid credentials present in cookies');
        }
        // If the token has (nearly) expired and there is a refreshToken: refresh tokens
        const { exp } = decodeToken(idToken);
        if ((Date.now() / 1000) - 60 > exp && refreshToken) {
            console.log('redirecting because token needs to be refreshed');
            return {
                status: '307',
                statusDescription: 'Temporary Redirect',
                headers: {
                    'location': [{
                        key: 'location',
                        value: `https://${domainName}${redirectPathAuthRefresh}?${stringifyQueryString({ requestedUri, nonce })}`
                    }],
                    'set-cookie': [
                        { key: 'set-cookie', value: `spa-auth-edge-nonce=${nonce}; ${cookieSettings.nonce}` },
                    ],
                    ...cloudFrontHeaders,
                }
            }
        }
        // Check for valid a JWT. This throws an error if there's no valid JWT:
        await validate(idToken, tokenJwksUri, tokenIssuer, clientId);
        console.log('JWT token is valid');
        if (request.uri === '/console/login') {
            console.log('login attempt, redirecting to index.html');
            return {
                status: '307',
                statusDescription: 'Temporary Redirect',
                headers: {
                    'location': [{
                        key: 'location',
                        value: '/console/index.html'
                    }],
                    ...cloudFrontHeaders,
                }
            }
        } else if (request.uri === '/console/logout') {
            console.log('logout attempt, redirecting to cognito endpoint and clear cookies');
            const logoutQueryString = stringifyQueryString({
                redirect_uri: `https://${domainName}${redirectPathSignOut}`,
                logout_uri: `https://${domainName}${redirectPathSignOut}`,
                client_id: clientId,
                response_type: 'code',
            });
            return {
                status: '307',
                statusDescription: 'Temporary Redirect',
                headers: {
                    'location': [{
                        key: 'location',
                        value: `https://${cognitoAuthDomain}/logout?${logoutQueryString}`
                    }],
                    'set-cookie': [
                        { key: 'set-cookie', value: `spa-auth-edge-nonce=none; Path=/; Secure; HttpOnly; SameSite=Lax; Expires=${new Date(0).toUTCString()}` },
                        { key: 'set-cookie', value: `spa-auth-edge-pkce=none; Path=/; Secure; HttpOnly; SameSite=Lax; Expires=${new Date(0).toUTCString()}` },
                        { key: 'set-cookie', value: `CognitoIdentityServiceProvider.${clientId}.LastAuthUser=none; domain=.${domainName}; Path=/; Secure; SameSite=Lax; Expires=${new Date(0).toUTCString()}`},
                        { key: 'set-cookie', value: `CognitoIdentityServiceProvider.${clientId}.${tokenUserName}.accessToken=none; domain=.${domainName}; Path=/; Secure; SameSite=Lax; Expires=${new Date(0).toUTCString()}` },
                        { key: 'set-cookie', value: `CognitoIdentityServiceProvider.${clientId}.${tokenUserName}.idToken=none; domain=.${domainName}; Path=/; Secure; SameSite=Lax; Expires=${new Date(0).toUTCString()}` },
                        { key: 'set-cookie', value: `CognitoIdentityServiceProvider.${clientId}.${tokenUserName}.refreshToken=none; domain=.${domainName}; Path=/; Secure; SameSite=Lax; Expires=${new Date(0).toUTCString()}` },
                        { key: 'set-cookie', value: `CognitoIdentityServiceProvider.${clientId}.${tokenUserName}.tokenScopesString=none; domain=.${domainName}; Path=/; Secure; SameSite=Lax; Expires=${new Date(0).toUTCString()}` },
                        { key: 'set-cookie', value: `CognitoIdentityServiceProvider.${clientId}.${tokenUserName}.userData=none; domain=.${domainName}; Path=/; Secure; SameSite=Lax; Expires=${new Date(0).toUTCString()}` }
                    ],
                    ...cloudFrontHeaders,
                }
            }
        }  
        console.log('not login/logout -> request for mpd');

        try {
            const response = await getContent(mediapackageDomain, requestedUri, keepAliveAgentOrigin);
            var manifest = response.toString();

            const decodedIdToken = decodeToken(idToken);
            const tokenUserGroups = decodedIdToken['cognito:groups'];
            console.log(`user group found: ${tokenUserGroups}`);

            if (!(tokenUserGroups) || !(tokenUserGroups.includes("premium"))) {
                console.log(`modifying manifest`);
                var options = {
                    ignoreAttributes : false,
                    ignoreNameSpace : false,
                    allowBooleanAttributes : false,
                    parseNodeValue : true,
                    parseAttributeValue : false,
                    trimValues: true,
                    cdataTagName: "__cdata", //default is 'false'
                    cdataPositionChar: "\\c",
                    localeRange: "", //To support non english character in tag/attribute values.
                    parseTrueNumberOnly: false,
                    attrValueProcessor: (a: any) => he.decode(a, {isAttributeValue: true}),//default is a=>a
                    tagValueProcessor : (a: any) => he.decode(a) //default is a=>a
                };
                var jsonObj = parse(response.toString(),options);
                // process manifest and cut high bitrates
                jsonObj.MPD.Period.AdaptationSet[0].Representation.splice(0, 7);
                jsonObj.MPD.Period.AdaptationSet[1].Representation.splice(0, 7);

                var defaultOptions = {
                    ignoreAttributes : false,
                    cdataTagName: "__cdata", //default is false
                    cdataPositionChar: "\\c",
                    format: true,
                    indentBy: "  ",
                    supressEmptyNode: false,
                    tagValueProcessor: (a: any)=> he.encode(a, { useNamedReferences: true}),// default is a=>a
                    attrValueProcessor: (a: any)=> he.encode(a, {isAttributeValue: 'isAttribute', useNamedReferences: true})// default is a=>a
                };
                var parser = new Parser(defaultOptions);
                manifest = parser.parse(jsonObj);  
                
            }

            console.log('returning manifest');
            return {
                status: '200',
                statusDescription: 'OK',
                body: manifest
            }


        } catch(err) {
            console.log(err);
            return {
                status: '500',
                statusDescription: `Error from Lambda@Edge`
            }
        }
    

    } catch (err) {
        console.log(err.message);
        if (request.uri === '/console/logout') {
            console.log('already loged out, redirecting to index.html');
            return {
                status: '307',
                statusDescription: 'Temporary Redirect',
                headers: {
                    'location': [{
                        key: 'location',
                        value: '/console/index.html'
                    }],
                    ...cloudFrontHeaders,
                }
            }
        }
        if (!(request.uri === '/console/login')) {
            console.log('returning manifest of unauthenticated video');
            return {
                status: '200',
                statusDescription: 'OK',
                body: unavailableManifest.replace(/CLOUDFRONT_DOMAIN/g, domainName),
                headers: {
                    'content-type': [{
                        key: 'Content-Type',
                        value: `application/dash+xml`
                    }],
                ...cloudFrontHeaders,
                }
            }
        }
        const pkce = randomBytes(32).toString('hex');
        const pkceHash = createHash('sha256').update(pkce, 'utf8').digest().toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const loginQueryString = stringifyQueryString({
            redirect_uri: `https://${domainName}${redirectPathSignIn}`,
            response_type: 'code',
            client_id: clientId,
            state: JSON.stringify({ nonce, requestedUri }),
            scope: oauthScopes.join(' '),
            code_challenge_method: 'S256',
            code_challenge: pkceHash,
        });
        console.log('redirecting to cognito for auth');
        return {
            status: '307',
            statusDescription: 'Temporary Redirect',
            headers: {
                'location': [{
                    key: 'location',
                    value: `https://${cognitoAuthDomain}/oauth2/authorize?${loginQueryString}`
                }],
                'set-cookie': [
                    { key: 'set-cookie', value: `spa-auth-edge-nonce=${nonce}; ${cookieSettings.nonce}` },
                    { key: 'set-cookie', value: `spa-auth-edge-pkce=${pkce}; ${cookieSettings.nonce}` }
                ],
                ...cloudFrontHeaders,
            }
        }
    }
}
// fecth an object from URL
const getContent = function(domain: string, path: string, keepAliveAgent: Agent): Promise<Buffer> {
    var start = Date.now();
    console.log('getContent-start', domain+path);
    return new Promise((resolve, reject) => {

        var options = {
            host: domain,
            port: 443,
            path: path,
            method: 'GET',
            agent: keepAliveAgent
        };
        
        var req = get(options, (response) => {
            const data = [new Uint8Array(0)];
            if (response.statusCode == 200) {
                response.on('data', (chunk) => data.push(chunk));
                response.on('end', () => {
                    var millis = Date.now() - start;
                    console.log('getContent-done', millis, 'code', response.statusCode);
                    resolve(Buffer.concat(data))
                });
            } else {
                reject(`getContent - issue downloading manifest- status code = ${response.statusCode}`)
            }
        }).on('error', (err) => reject(err));
        // set request timeout
        var timeoutCallback = function() {
            console.log('getContent-timeout');
            req.abort();
        };
        req.setTimeout(DEFAULT_HTTP_REQUEST_TIMEOUT, timeoutCallback);
    })
};