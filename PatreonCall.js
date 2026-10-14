import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand} from "@aws-sdk/lib-dynamodb";
import crypto from 'node:crypto';

const ssmClient = new SSMClient({});
const client = new DynamoDBClient({});
const dynamo = DynamoDBDocumentClient.from(client);
const tableName = "patrons_table";
let secrets, key; // Cache outside handler to avoid calling ssm during subsequent warm invocations

//Cloudfront requires custom variation of base64 encoding
//Could import @aws-sdk/cloudfront-signer but this works already
function toCloudFrontSafeBase64(standardB64String) {
  return standardB64String
    .replace(/\+/g, '-')
    .replace(/\//g, '~')
    .replace(/=/g, '_');
}

async function patreon_request(code){
    const api_response = await fetch("https://www.patreon.com/api/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            client_id: "LcSa28h6RGVElR6V5GAzU_x599HL9VzCy-MWTzbXSizp-A3iMNUaee0HZnD-1eik",
            client_secret: secrets.secretV,
            redirect_uri: "https://d3njrza7z5bkut.cloudfront.net/auth.html"
        })
    });

    if (!api_response.ok) {
        const errBody = await api_response.text();
        throw new Error("Patreon token error", errBody)
    }

    const tokenData = await api_response.json();

    if (!tokenData.access_token || !tokenData.refresh_token) {
        throw new Error(`Patreon access and/or refresh token missing: ${JSON.stringify(tokenData)}`);
    }

    const access_token = tokenData.access_token;

    const params = new URLSearchParams({
        'include': 'memberships.currently_entitled_tiers,memberships.campaign',
        'fields[member]': 'next_charge_date'
    });

    const patreon_url = new URL(`https://www.patreon.com/api/oauth2/v2/identity?${params}`);

    const patreon_profile = await fetch(patreon_url, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${access_token}`,
            'Accept': 'application/json'
        }
    });

    if (!patreon_profile.ok) {
        throw new Error(`Error: ${patreon_profile.status}`);
    }

    const patreon_json = await patreon_profile.json();

    return {"json": patreon_json, "tokens": tokenData};
}

function encrypt_token(key, token, random_s) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    cipher.setAAD(Buffer.from(random_s));

    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    return `${iv.toString('hex')}.${encrypted}.${authTag}`;
}

async function fetch_secrets() {
    const patreon_command = new GetParameterCommand({ Name: "patreon_secret", WithDecryption: true });
    const sign_key_command = new GetParameterCommand({ Name: "sign_key", WithDecryption: true });
    const aes_key_command = new GetParameterCommand({ Name: "aes_master_key", WithDecryption: true });

    const [patreonRes, signKeyRes, masterKeyRes] = await Promise.all([
        ssmClient.send(patreon_command),
        ssmClient.send(sign_key_command),
        ssmClient.send(aes_key_command)
    ]);

    const secretValue = patreonRes.Parameter?.Value;
    const privateKeyPem = signKeyRes.Parameter?.Value;
    const masterKey = masterKeyRes.Parameter?.Value;

    if (!secretValue || !privateKeyPem || !masterKey) {
        throw new Error("Failed to fetch secrets");
    }

    return {"secretV": secretValue, "privateK": privateKeyPem, "masterK": masterKey};
}

async function assign_secrets(){
    if(secrets) return;
    const fetched = await fetch_secrets();
    const derived_key = Buffer.from(fetched.masterK, 'hex');
    secrets = fetched;
    key = derived_key;
}


export const handler = async (event) => {
    try{
        const current_time = Math.floor(Date.now() / 1000);
        if (!event?.queryStringParameters) {
            return {
                statusCode: 400,
                body: JSON.stringify({ message: "Bad Request." }),
            };
        }

        const code = event.queryStringParameters?.code;
        if (!code) {
            return { statusCode: 400, body: JSON.stringify({ message: "Missing 'code' parameter." }) };
        }

        await assign_secrets();

        const secure_id = crypto.randomUUID();
        const patreon_object = await patreon_request(code);
        const patreon_profile = patreon_object.json;
        const tokens_object = patreon_object.tokens;
        const access_expires_in = tokens_object.expires_in;
        const access_token = encrypt_token(key, tokens_object.access_token, secure_id);
        const refresh_token = encrypt_token(key, tokens_object.refresh_token, secure_id);

        const patreon_id = patreon_profile.data.id;
        const member = patreon_profile.included?.find((item) => item.type === "member");
        const entitled_tiers = member?.relationships?.currently_entitled_tiers?.data ?? [];
        const tier_id_user = entitled_tiers.length > 0 ? entitled_tiers[0].id : null;
        const tier_id_own = "29618353";

        if (!tier_id_user || tier_id_user !== tier_id_own) {
            return {
                statusCode:401,
                body: JSON.stringify({ message: "Not a patron." }),
            }
        }

        const expire_date_cookie = current_time + 604800; // a week
        const expire_date_token = current_time + access_expires_in;
        const date_str = member?.attributes?.next_charge_date;
        if (!date_str) {
            throw new Error("next_charge_date is missing or null");
        }
        const parsed_date = Date.parse(date_str);
        if (Number.isNaN(parsed_date)) {
            throw new Error("next_charge_date is not a valid date string");
        }
        const expire_date_sub = Math.floor(parsed_date / 1000);

        await dynamo.send(
          new PutCommand({
              TableName: tableName,
              Item: {
                  patreon_id: patreon_id,
                  random_string: secure_id,
                  token_expires_at: expire_date_token,
                  access_t: access_token,
                  refresh_t: refresh_token,
                  next_charge_date: expire_date_sub,
              },
          })
        );

        const policy = {
            "Statement": [
                {
                    "Resource": "https://d3njrza7z5bkut.cloudfront.net/contents/*",
                    "Condition": {
                        "DateLessThan": {
                            "AWS:EpochTime":expire_date_cookie
                        }
                    }
                }
            ]
        };

        const policyString = JSON.stringify(policy);

        const standardPolicyB64 = Buffer.from(policyString, 'utf8').toString('base64');
        const cloudFrontPolicyCookieValue = toCloudFrontSafeBase64(standardPolicyB64);

        const signer = crypto.createSign('RSA-SHA256');
        signer.update(policyString);
        const signatureBuffer = signer.sign(secrets.privateK);

        const standardSignatureB64 = signatureBuffer.toString('base64');
        const cloudFrontSignatureCookieValue = toCloudFrontSafeBase64(standardSignatureB64);

        const response = {
            statusCode: 200,
            cookies: [
                `CloudFront-Policy=${cloudFrontPolicyCookieValue}; Path=/; Secure; HttpOnly; SameSite=Lax; Partitioned`,
                `CloudFront-Signature=${cloudFrontSignatureCookieValue}; Path=/; Secure; HttpOnly; SameSite=Lax; Partitioned`,
                `CloudFront-Key-Pair-Id=K15VKU3HUVYLOO; Path=/; Secure; HttpOnly; SameSite=Lax; Partitioned`,
                `CloudFront-Hash-Algorithm=SHA256; Path=/; Secure; HttpOnly; SameSite=Lax; Partitioned`,
                `secure-id=${secure_id}; Path=/; Secure; HttpOnly; SameSite=Lax; Partitioned`
            ],
        };
        return response;
        }
        catch(e){
            console.log("Catch:", e);
            return {
                statusCode: 500,
                body: JSON.stringify({ message: 'Internal server error' }),
            };
        }
};
