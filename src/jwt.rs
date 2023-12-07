use josekit::{
    jws::{JwsHeader, JwsSigner},
    jwt::JwtPayload,
};
use thiserror::Error;
#[cfg(feature = "auth_during_comm")]
use verder_helpen_proto::StartRequestAuthOnly;

use crate::types::AuthSelectParams;

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("Invalid Structure for key {0}")]
    InvalidStructure(&'static str),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("JWT error: {0}")]
    Jwt(#[from] josekit::JoseError),
    #[error("Verder Helpen JWE error: {0}")]
    Jwe(#[from] verder_helpen_jwt::Error),
}

#[cfg(feature = "auth_during_comm")]
pub fn sign_start_auth_request(
    request: StartRequestAuthOnly,
    kid: &str,
    signer: &dyn JwsSigner,
) -> Result<String, JwtError> {
    let mut sig_header = JwsHeader::new();
    sig_header.set_token_type("JWT");
    sig_header.set_key_id(kid);
    let mut sig_payload = JwtPayload::new();
    sig_payload.set_claim("request", Some(serde_json::to_value(request)?))?;
    sig_payload.set_issued_at(&std::time::SystemTime::now());
    sig_payload
        .set_expires_at(&(std::time::SystemTime::now() + std::time::Duration::from_secs(5 * 60)));
    Ok(josekit::jwt::encode_with_signer(
        &sig_payload,
        &sig_header,
        signer,
    )?)
}

/// Serialize and sign a set of AuthSelectParams for use in the auth-select menu
pub fn sign_auth_select_params(
    params: AuthSelectParams,
    signer: &dyn JwsSigner,
) -> Result<String, JwtError> {
    let mut sig_header = JwsHeader::new();
    sig_header.set_token_type("JWT");
    let mut sig_payload = JwtPayload::new();
    sig_payload.set_subject("verder-helpen-widget-params");

    sig_payload.set_claim("purpose", Some(serde_json::to_value(&params.purpose)?))?;
    sig_payload.set_claim("start_url", Some(serde_json::to_value(&params.start_url)?))?;
    sig_payload.set_claim(
        "cancel_url",
        Some(serde_json::to_value(&params.cancel_url)?),
    )?;
    sig_payload.set_claim(
        "display_name",
        Some(serde_json::to_value(&params.display_name)?),
    )?;

    sig_payload.set_issued_at(&std::time::SystemTime::now());
    sig_payload
        .set_expires_at(&(std::time::SystemTime::now() + std::time::Duration::from_secs(5 * 60)));

    let jws = josekit::jwt::encode_with_signer(&sig_payload, &sig_header, signer)?;

    Ok(jws)
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use josekit::{
        jws::{JwsSigner, JwsVerifier},
        jwt::JwtPayloadValidator,
    };
    use verder_helpen_jwt::SignKeyConfig;
    use verder_helpen_proto::StartRequestAuthOnly;

    use super::{sign_auth_select_params, sign_start_auth_request};
    use crate::types::AuthSelectParams;

    const RSA_PRIVKEY: &str = "{\"type\":\"RSA\",\"key\":\"-----BEGIN PRIVATE \
                               KEY-----\\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDn/\
                               BGtPZPgYa+5\\nBhxaMuv+UV7nWxNXYUt3cYBoyIc3xD9VP9cSE/\
                               +RnrTjaXUGPZWlnbIzG/b3gkrA\\\
                               nEIg1zfjxUth34N+QycnjJf0tkcrZaR7q0JYEH2ZiAaMzAI11dzNuX3rHX8d69pOi\\\
                               nu+T3WvMK/PDq9XTyO2msDI3lpgxTgjT9xUnCLTduH+yStoAHXXSZBKqLVBT/bPoe\\\
                               nS5/v7/H9sALG+JYLI8J3/CRc2kWFNxGV8V7IpzLSnAXHU4sIMnWpjuhT7PXBzKl4\\\
                               n4d6JRLGuJIeVZpPbiR74nvwYZWacJl278xG66fmG+BqJbGeEgGYTEljq9G4yXCRt\\\
                               nGo5+3lBNAgMBAAECggEARY9EsaCMLbS83wrhB37LWneFsHOTqhjHaypCaajvOp6C\\\
                               nqwo4b/hFIqHm9WWSrGtc6ssNOtwAwphz14Fdhlybb6j6tX9dKeoHui+S6c4Ud/pY\\\
                               nReqDgPr1VR/OkqVwxS8X4dmJVCz5AHrdK+eRMUY5KCtOBfXRuixsdCVTiu+uNH99\\\
                               nQC3kID1mmOF3B0chOK4WPN4cCsQpfOvoJfPBcJOtyxUSLlQdJH+04s3gVA24nCJj\\\
                               n66+AnVkjgkyQ3q0Jugh1vo0ikrUW8uSLmg40sT5eYDN9jP6r5Gc8yDqsmYNVbLhU\\\
                               npY8XR4gtzbtAXK8R2ISKNhOSuTv4SWFXVZiDIBkuIQKBgQD3qnZYyhGzAiSM7T/R\\\
                               nWS9KrQlzpRV5qSnEp2sPG/YF+SGAdgOaWOEUa3vbkCuLCTkoJhdTp67BZvv/657Q\\\
                               n2eK2khsYRs02Oq+4rYvdcAv/wS2vkMbg6CUp1w2/pwBvwFTXegr00k6IabXNcXBy\\\
                               nkAjMsZqVDSdQByrf80AlFyEsOQKBgQDvyoUDhLReeDNkbkPHL/EHD69Hgsc77Hm6\\\
                               nMEiLdNljTJLRUl+DuD3yKX1xVBaCLp9fMJ/mCrxtkldhW+i6JBHRQ7vdf11zNsRf\\\
                               n2Cud3Q97RMHTacCHhEQDGnYkOQNTRhk8L31N0XBKfUu0phSmVyTnu2lLWmYJ8hyO\\\
                               nyOEB19JstQKBgQC3oVw+WRTmdSBEnWREBKxb4hCv/ib+Hb8qYDew7DpuE1oTtWzW\\\
                               ndC/uxAMBuNOQMzZ93kBNdnbMT19pUXpfwC2o0IvmZBijrL+9Xm/lr7410zXchqvu\\\
                               n9jEX5Kv8/gYE1cYSPhsBiy1PV5HE0edeCg18N/M1sJsFa0sO4X0eAxhFgQKBgQC7\\\
                               niQDkUooaBBn1ZsM9agIwSpUD8YTOGdDNy+tAnf9SSNXePXUT+CkCVm6UDnaYE8xy\\\
                               nzv2PFUBu1W/fZdkqkwEYT8gCoBS/AcstRkw+Z2AvQQPxyxhXJBto7e4NwEUYgI9F\\\
                               n4cI29SDEMR/fRbCKs0basVjVJPr+tkqdZP+MyHT6rQKBgQCT1YjY4F45Qn0Vl+sZ\\\
                               nHqwVHvPMwVsexcRTdC0evaX/09s0xscSACvFJh5Dm9gnuMHElBcpZFATIvFcbV5Y\\\
                               nMbJ/NNQiD63NEcL9VXwT96sMx2tnduOq4sYzu84kwPQ4ohxmPt/7xHU3L8SGqoec\\\
                               nBs6neR/sZuHzNm8y/xtxj2ZAEw==\\n-----END PRIVATE KEY-----\"}";
    const RSA_PUBKEY: &str =
        "{\"type\":\"RSA\",\"key\":\"-----BEGIN PUBLIC \
         KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5/wRrT2T4GGvuQYcWjLr\\n/\
         lFe51sTV2FLd3GAaMiHN8Q/VT/XEhP/kZ6042l1Bj2VpZ2yMxv294JKwBCINc34\\\
         n8VLYd+DfkMnJ4yX9LZHK2Wke6tCWBB9mYgGjMwCNdXczbl96x1/HevaTorvk91rz\\\
         nCvzw6vV08jtprAyN5aYMU4I0/cVJwi03bh/skraAB110mQSqi1QU/2z6Hkuf7+/x\\n/bACxviWCyPCd/\
         wkXNpFhTcRlfFeyKcy0pwFx1OLCDJ1qY7oU+z1wcypeOHeiUSx\\nriSHlWaT24ke+J78GGVmnCZdu/\
         MRuun5hvgaiWxnhIBmExJY6vRuMlwkbRqOft5Q\\nTQIDAQAB\\n-----END PUBLIC KEY-----\"}";

    #[cfg(feature = "auth_during_comm")]
    #[test]
    fn test_sign_start_auth_request() {
        let signer = Box::<dyn JwsSigner>::try_from(
            serde_json::from_str::<SignKeyConfig>(RSA_PRIVKEY).unwrap(),
        )
        .unwrap();
        let verifier = Box::<dyn JwsVerifier>::try_from(
            serde_json::from_str::<SignKeyConfig>(RSA_PUBKEY).unwrap(),
        )
        .unwrap();

        let result = sign_start_auth_request(
            StartRequestAuthOnly {
                purpose: "test".into(),
                auth_method: "someauth".into(),
                comm_url: "https://example.com".into(),
                attr_url: None,
            },
            "some",
            signer.as_ref(),
        )
        .unwrap();

        let (payload, header) =
            josekit::jwt::decode_with_verifier(result, verifier.as_ref()).unwrap();
        assert_eq!(header.key_id(), Some("some"));
        let mut validator = JwtPayloadValidator::new();
        validator.set_base_time(std::time::SystemTime::now());
        validator.validate(&payload).unwrap();
        let req = serde_json::from_value::<StartRequestAuthOnly>(
            payload.claim("request").unwrap().clone(),
        )
        .unwrap();
        assert_eq!(req.purpose, "test");
        assert_eq!(req.auth_method, "someauth");
        assert_eq!(req.comm_url, "https://example.com");
        assert_eq!(req.attr_url, None);
    }

    #[test]
    fn test_sign_auth_select_params() {
        let signer = Box::<dyn JwsSigner>::try_from(
            serde_json::from_str::<SignKeyConfig>(RSA_PRIVKEY).unwrap(),
        )
        .unwrap();
        let verifier = Box::<dyn JwsVerifier>::try_from(
            serde_json::from_str::<SignKeyConfig>(RSA_PUBKEY).unwrap(),
        )
        .unwrap();

        let result = sign_auth_select_params(
            AuthSelectParams {
                purpose: "test".into(),
                start_url: "https://example.com".into(),
                cancel_url: "https://example.com/cancel".into(),
                display_name: "bla".into(),
            },
            signer.as_ref(),
        )
        .unwrap();

        let (payload, _) = josekit::jwt::decode_with_verifier(result, verifier.as_ref()).unwrap();
        assert_eq!(payload.claim("purpose").unwrap().as_str().unwrap(), "test");
        assert_eq!(
            payload.claim("start_url").unwrap().as_str().unwrap(),
            "https://example.com"
        );
        assert_eq!(
            payload.claim("cancel_url").unwrap().as_str().unwrap(),
            "https://example.com/cancel"
        );
        assert_eq!(
            payload.claim("display_name").unwrap().as_str().unwrap(),
            "bla"
        );
    }
}
