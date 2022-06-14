use super::super::state::State;
use super::{URLs, HTTP};
use aes_gcm::aead::generic_array::{typenum::U12, GenericArray};
use aes_gcm::aead::{AeadInPlace, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64;
use rand::Rng;
use reqwest::{header, Method, Response};
use rsa::pkcs8::DecodePublicKey;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{self, SystemTimeError, UNIX_EPOCH};
use thiserror::Error;
use urlencoding;

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginErrorData {
    machine_id: String,
    uid: Option<u64>,
    login_first_factor: Option<String>,
    support_uri: Option<String>,
    auth_token: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionCookie {
    name: String,
    value: String,
    expires: String,
    expires_timestamp: u64,
    domain: String,
    path: String,
    secure: bool,
    httponly: bool,
}
#[derive(Serialize, Deserialize, Debug)]

pub struct LoginSuccessResponse {
    session_key: String,
    uid: u64,
    secret: String,
    access_token: String,
    machine_id: String,
    session_cookies: Vec<SessionCookie>,
    analytics_claim: String,
    identifier: String,
    user_storage_key: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginErrorResponse {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
    code: u16,
    error_data: LoginErrorData,
    error_subcode: u32,
    is_transient: bool,
    error_user_title: String,
    error_user_msg: String,
    fbtrace_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]

pub enum LoginResponse {
    Success(LoginSuccessResponse),
    Error { error: LoginErrorResponse },
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MobileConfigField {
    k: usize,
    bln: Option<u8>,
    i64: Option<i64>,
    str: Option<String>,
    pname: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MobileConfigItem {
    fields: Vec<MobileConfigField>,
    hash: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MobileConfig {
    configs: HashMap<String, MobileConfigItem>,
    query_hash: Option<String>,
    one_query_hash: Option<String>,
    ts: usize,
    ep_hash: String,
}
#[derive(Error, Debug)]
#[error("Couldn't find field in MobileConfig")]
struct MobileConfigFindError;

impl MobileConfig {
    fn find(&self, number: usize, field_k: usize) -> Option<&MobileConfigField> {
        self.configs.get(&number.to_string()).and_then(|config| {
            for (_, field) in config.fields.iter().enumerate() {
                if field.k == field_k {
                    return Some(field);
                }
            }
            None
        })
    }
}
#[derive(Serialize, Deserialize)]
pub struct PasswordKeyResponse {
    pub public_key: String,
    pub key_id: i64,
    pub seconds_to_live: usize,
}
#[derive(Error, Debug)]
enum EncryptPasswordError {
    #[error("Encryption pubkey is missing from state")]
    EncryptionPubkeyMissingError,
    #[error("Encryption key id is missing from state")]
    EncryptionKeyIdMissingError,
    #[error("PKCS8Error: {0}")]
    PKCS8Error(#[from] rsa::pkcs8::spki::Error),
    #[error("RSAError: {0}")]
    RSAError(#[from] rsa::errors::Error),
    #[error("SystemTimeError: {0}")]
    SystemTimeError(#[from] SystemTimeError),
    #[error("AESGcm Error: {0}")]
    AESGcmError(#[from] aes_gcm::Error),
}
#[derive(Error, Debug)]

pub enum LoginError {
    #[error("Reqwest Error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("EncryptPasswordError Error: {0}")]
    EncryptPasswordError(#[from] EncryptPasswordError),
    #[error("Invalid username or password")]
    Requires2FA,
    #[error("Login requires a 2FA code")]
    InvalidCredentials,
    #[error("Unknown LoginError")]
    Unknown,
    #[error("Rate limit exceeded")]
    RateLimit,
}

impl HTTP {
    pub async fn pwd_key_fetch(
        &self,
        mut state: &mut State,
    ) -> Result<PasswordKeyResponse, reqwest::Error> {
        let mut req: HashMap<String, String> = HashMap::from([
            ("version".to_owned(), "2".to_owned()),
            ("flow".to_owned(), "CONTROLLER_INITIALIZATION".to_owned()),
            ("method".to_owned(), "GET".to_owned()),
            (
                "fb_api_req_friendly_name".to_owned(),
                "pwdKeyFetch".to_owned(),
            ),
            (
                "fb_api_caller_class".to_owned(),
                "com.facebook.auth.login.AuthOperations".to_owned(),
            ),
            (
                "access_token".to_owned(),
                state.application.access_token().to_owned(),
            ),
        ]);
        for (key, value) in self.params(&state) {
            req.insert(key.to_owned(), value.to_owned());
        }
        let formatted = self.format(&state, req, false, None);

        let response = self
            .request_with_subdomain(URLs::Graph, Method::POST, "pwd_key_fetch")
            .headers(self.headers(&state))
            .body(formatted)
            .send()
            .await?
            .json::<PasswordKeyResponse>()
            .await?;
        state.session.password_encryption_pubkey = Some(response.public_key.clone());
        state.session.password_encryption_key_id = Some(response.key_id);
        Ok(response)
    }

    pub async fn mobile_config_sessionless(
        &self,
        state: &mut State,
    ) -> Result<MobileConfig, reqwest::Error> {
        if state.device.uuid.is_none() {
            state.generate();
        }
        let uuid = state.device.uuid.as_ref().unwrap();
        let access_token = state.application.access_token();
        let mut req: HashMap<String, String> = HashMap::from([
            (
                "query_hash".to_owned(),
                "4d43269ae03c31739a1e8542bc0d1da3c0acb1a85de6903ee9f669e2bc4b7af7".to_owned(),
            ),
            (
                "one_query_hash".to_owned(),
                "835e01d247719369d2affa524786437bd4ad9443e351d95eb95d23d4aed357c7".to_owned(),
            ),
            ("bool_opt_policy".to_owned(), "3".to_owned()),
            ("device_id".to_owned(), uuid.to_owned()),
            ("api_version".to_owned(), "8".to_owned()),
            ("fetch_type".to_owned(), "SYNC_FULL".to_owned()),
            ("unit_type".to_owned(), "1".to_owned()),
            ("access_token".to_owned(), access_token.to_owned()),
        ]);
        for (key, value) in self.params(state) {
            req.insert(key.to_owned(), value.to_owned());
        }
        let mut headers = self.headers(state);
        headers.remove("x-fb-rmd");
        let formatted = self.format(state, req, false, None);
        let response = self
            .request_with_subdomain(URLs::BGraph, Method::POST, "mobileconfigsessionless")
            .headers(headers)
            .body(formatted)
            .send()
            .await?
            .json::<MobileConfig>()
            .await?;
        if let Some(password_encryption_key_id) = response.find(15712, 1) {
            state.session.password_encryption_key_id = password_encryption_key_id.i64;
        }

        if let Some(password_encryption_pubkey) = response.find(15712, 2) {
            state.session.password_encryption_pubkey = password_encryption_pubkey.str.clone();
        }
        Ok(response)
    }

    pub async fn login(
        self,
        state: &mut State,
        email: String,
        mut password: String,
        encrypt_password: bool,
    ) -> Result<(), LoginError> {
        if encrypt_password {
            password = self.encrypt_password(state, password)?;
        }
        self.internal_login(
            state,
            vec![
                ("email".to_string(), email),
                ("password".to_string(), password),
                ("credentials_type".to_string(), "password".to_string()),
            ],
        )
        .await?;
        Ok(())
    }
    async fn internal_login(
        self,
        state: &mut State,
        details: Vec<(String, String)>,
    ) -> Result<(), LoginError> {
        if state.device.uuid.is_none() || state.device.adid.is_none() {
            state.generate();
        }
        let adid = state.device.adid.as_ref().unwrap();
        let uuid = state.device.uuid.as_ref().unwrap();
        let jazoest = format!("2{}", uuid.chars().fold(0, |acc, i| acc + i as u32));
        println!("\n\nadid: {}\n\n\n", adid);
        let mut req: HashMap<String, String> = HashMap::from([
            ("adid".to_owned(), adid.to_owned()),
            ("api_key".to_owned(), state.application.client_id.to_owned()),
            ("community_id".to_owned(), "".to_owned()),
            ("secure_family_device_id".to_owned(), "".to_owned()),
            ("cpl".to_owned(), "true".to_owned()),
            ("currently_logged_in_userid".to_owned(), "0".to_owned()),
            ("device_id".to_owned(), uuid.as_str().to_owned()),
            (
                "fb_api_caller_class".to_owned(),
                "AuthOperations$PasswordAuthOperation".to_owned(),
            ),
            (
                "fb_api_req_friendly_name".to_owned(),
                "authenticate".to_owned(),
            ),
            ("format".to_owned(), "json".to_owned()),
            ("generate_analytics_claim".to_owned(), "1".to_owned()),
            ("generate_machine_id".to_owned(), "1".to_owned()),
            ("generate_session_cookies".to_owned(), "1".to_owned()),
            ("jazoest".to_owned(), jazoest),
            ("meta_inf_fbmeta".to_owned(), "NO_FILE".to_owned()),
            ("source".to_owned(), "login".to_owned()),
            ("try_num".to_owned(), "1".to_owned()),
        ]);
        req.extend(details.into_iter());
        for (key, value) in self.params(&state) {
            req.insert(key.to_owned(), value.to_owned());
        }
        let formatted = self.format(
            &state,
            req,
            true,
            Some(vec![(
                "access_token".to_owned(),
                state.application.access_token(),
            )]),
        );

        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers.insert(
            header::HeaderName::from_static("x-fb-friendly-name"),
            header::HeaderValue::from_static("authenticate"),
        );
        headers.remove("x-fb-rmd");
        println!("Request: \n{:?}\n\n\n", &formatted);
        let response = self
            .request_with_subdomain(URLs::BGraph, Method::POST, "auth/login")
            .headers(headers)
            .body(formatted)
            .send()
            .await?
            .json::<LoginResponse>()
            .await?;
        match response {
            LoginResponse::Success(success) => {
                state.session.access_token = Some(success.access_token);
                state.session.uid = Some(success.uid);
                state.session.machine_id = Some(success.machine_id);
                state.session.login_first_factor = None;
            }
            // TODO: Give more information about errors
            LoginResponse::Error { error } => match error.code {
                401 => return Err(LoginError::InvalidCredentials),
                406 => return Err(LoginError::Requires2FA),
                613 => return Err(LoginError::RateLimit),
                _ => return Err(LoginError::Unknown),
            },
        }
        Ok(())
    }
    fn encrypt_password(
        &self,
        state: &mut State,
        password: String,
    ) -> Result<String, EncryptPasswordError> {
        let cipher_rsa = RsaPublicKey::from_public_key_pem(
            &state
                .session
                .password_encryption_pubkey
                .clone()
                .ok_or(EncryptPasswordError::EncryptionPubkeyMissingError)?,
        )?;
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let mut rng = rand::thread_rng();
        let rand_key: [u8; 32] = rng.gen();
        let encrypted_rand_key = cipher_rsa.encrypt(&mut rng, padding, &rand_key)?;

        let cipher_aes = Aes256Gcm::new(&Key::from_slice(&rand_key));
        let iv: [u8; 12] = rng.gen();
        let nonce: &GenericArray<u8, U12> = Nonce::from_slice(&iv);
        let time = time::SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        println!("time: {}", time);
        let mut password_vec: Vec<u8> = Vec::new();
        password_vec.extend_from_slice(&password.as_bytes());
        let tag = cipher_aes.encrypt_in_place_detached(
            &nonce,
            time.to_string().as_bytes(),
            &mut password_vec,
        )?;
        let mut result: Vec<u8> = Vec::new();
        match state.session.password_encryption_key_id {
            Some(key_id) => {
                // TODO: make this nicer/check if this is the right way to do this
                let mut arr = [vec![1u8], key_id.to_le_bytes().to_vec()].concat();
                arr = arr.into_iter().rev().skip_while(|&x| x == 0).collect();
                arr.reverse();
                result.extend_from_slice(&arr);
                println!("arr: {:?}", arr);
            }
            None => {
                return Err(EncryptPasswordError::EncryptionKeyIdMissingError);
            }
        }
        result.extend_from_slice(&iv);
        result.extend_from_slice(&[0, 1]); // encrypted_rand_key len bytes (256)
        result.extend_from_slice(&encrypted_rand_key);
        result.extend_from_slice(&tag);
        result.extend_from_slice(&password_vec);
        let encoded = base64::encode(result);
        Ok(format!("#PWD_MSGR:1:{}:{}", time, encoded))
    }
}
