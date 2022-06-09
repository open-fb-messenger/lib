use super::super::state::State;

use super::{URLs, HTTP};
use reqwest::{header, Method, Response};
use std::collections::HashMap;
use std::ops::DerefMut;

impl HTTP {
    pub async fn mobile_config_sessionless(self, state: &mut State) {
        if state.device.uuid.is_none() {
            state.generate();
        }
        let uuid = state.device.uuid.as_ref().unwrap();
        let access_token = state.application.access_token();
        let mut form_data: HashMap<&str, &str> = HashMap::from([
            (
                "query_hash",
                "4d43269ae03c31739a1e8542bc0d1da3c0acb1a85de6903ee9f669e2bc4b7af7",
            ),
            (
                "one_query_hash",
                "835e01d247719369d2affa524786437bd4ad9443e351d95eb95d23d4aed357c7",
            ),
            ("bool_opt_policy", "3"),
            ("device_id", uuid),
            ("api_version", "8"),
            ("fetch_type", "SYNC_FULL"),
            ("unit_type", "1"),
            ("access_token", access_token.as_str()),
        ]);
        for (key, value) in self.params(state) {
            form_data.insert(key, value);
        }
        let mut headers = self.headers(state);
        headers.remove("x-fb-rmd");
        let formatted = self.format(state, form_data, Some(false), None);
        let response = self
            .request_with_subdomain(URLs::BGraph, Method::POST, "mobileconfigsessionless")
            .headers(headers)
            .body(formatted)
            .send()
            .await;

        if let Ok(response) = response {
            println!("{:?}", response);
        }
    }

    async fn login(self, state: &mut State) {
        if state.device.uuid.is_none() || state.device.adid.is_none() {
            state.generate();
        }
        let adid = state.device.adid.as_ref().unwrap();
        let uuid = state.device.uuid.as_ref().unwrap();
        let jazoest = format!("2{}", uuid.chars().fold(0, |acc, i| acc + i as u32));

        let mut form_data: HashMap<&str, &str> = HashMap::from([
            ("adid", adid.as_str()),
            ("api_key", state.application.client_id),
            ("community_id", ""),
            ("secure_family_device_id", ""),
            ("cpl", "true"),
            ("currently_logged_in_userid", "0"),
            ("device_id", uuid.as_str()),
            (
                "fb_api_caller_class",
                "AuthOperations$PasswordAuthOperation",
            ),
            ("fb_api_req_friendly_name", "authenticate"),
            ("format", "json"),
            ("generate_analytics_claim", "1"),
            ("generate_machine_id", "1"),
            ("generate_session_cookies", "1"),
            ("jazoest", jazoest.as_str()),
            ("meta_inf_fbmeta", "NO_FILE"),
            ("source", "login"),
            ("try_num", "1"),
        ]);
        form_data.insert("email", "email");
        form_data.insert("password", "encrypted_password");
        form_data.insert("credentials_type", "password");

        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers.insert(
            header::HeaderName::from_static("x-fb-friendly-name"),
            header::HeaderValue::from_static("authenticate"),
        );

        let response: Response = self
            .request_with_subdomain(URLs::BGraph, Method::POST, "auth/login")
            .headers(headers)
            .form(&form_data)
            .send()
            .await
            .unwrap();

        println!("{:?}", response);
    }
}
