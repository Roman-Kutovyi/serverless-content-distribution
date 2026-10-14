import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import crypto from 'node:crypto';

const ssmClient = new SSMClient({});
let secrets; // Cache outside handler to avoid calling ssm during subsequent warm invocations

//Cloudfront requires custom variation of base64 encoding
//Could import @aws-sdk/cloudfront-signer but this works already
function toCloudFrontSafeBase64(standardB64String) {
  return standardB64String
    .replace(/\+/g, '-')
    .replace(/\//g, '~')
    .replace(/=/g, '_');
}


async function fetch_secrets() {
    const sign_key_command = new GetParameterCommand({ Name: "sign_key", WithDecryption: true });

    const signKeyRes = await ssmClient.send(sign_key_command);

    const privateKeyPem = signKeyRes.Parameter?.Value;
    console.log(privateKeyPem);
    if ( !privateKeyPem) {
        throw new Error("Failed to fetch secrets");
    }

    return { "privateK": privateKeyPem};
}

async function assign_secrets(){
    if(secrets) return;
    const fetched = await fetch_secrets();
    secrets = fetched;
}


export const handler = async (event) => {
    try{
        await assign_secrets();
        const current_time = Math.floor(Date.now() / 1000);

        const expire_date_cookie = current_time + 3600; // an hour

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
                `CloudFront-Hash-Algorithm=SHA256; Path=/; Secure; HttpOnly; SameSite=Lax; Partitioned`
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
