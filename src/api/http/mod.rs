use reqwest::Response;
use reqwest::{self, header::HeaderMap, Method};
use std::collections::HashMap;
use std::fs::read;
use std::io::{BufReader, Bytes};
use zstd::stream::zio::Reader;

use super::state::State;
use std::convert::TryInto;

#[derive(Clone)]
pub struct DecompressableResponse {
    pub response: Response,
    pub decompressed: bool,
    pub data: String,
}
pub enum URLs {
    A,
    B,
    Graph,
    BGraph,
    Rupload,
}
impl URLs {
    fn as_str(&self) -> &'static str {
        match self {
            URLs::A => "https://api.facebook.com",
            URLs::B => "https://b-api.facebook.com",
            URLs::Graph => "https://graph.facebook.com",
            URLs::BGraph => "https://b-graph.facebook.com",
            URLs::Rupload => "https://rupload.facebook.com",
        }
    }
}
pub struct HTTP {
    pub client: reqwest::Client,
    pub decoder_dict: zstd::dict::DecoderDictionary<'static>,
}

impl HTTP {
    pub fn new() -> HTTP {
        // read zstd-dict.dat to binary u8
        let mut zstd_dict: &[u8] = &read("zstd-dict.dat").unwrap();
        HTTP {
            client: reqwest::Client::new(),
            decoder_dict: zstd::dict::DecoderDictionary::copy(zstd_dict),
        }
    }
    pub fn request_with_subdomain(
        &self,
        url: URLs,
        method: Method,
        path: &str,
    ) -> reqwest::RequestBuilder {
        let url_path = format!("{}/{}", url.as_str(), path);
        self.client.request(method, url_path)
    }
    fn headers(&self, state: &State) -> HeaderMap {
        let mut headers = HashMap::from([
            (
                "x-fb-connection-quality".to_string(),
                state.device.connection_quality.to_string(),
            ),
            (
                "x-fb-connection-type".to_string(),
                state.device.connection_type.to_string(),
            ),
            (
                "user-agent".to_string(),
                state.device.user_agent.to_string(),
            ),
            ("x-tigon-is-retry".to_string(), "False".to_string()),
            ("x-fb-http-engine".to_string(), "Liger".to_string()),
            ("x-fb-client-ip".to_string(), "True".to_string()),
            ("x-fb-server-cluster".to_string(), "True".to_string()),
            ("x-fb-sim-hni".to_string(), state.carrier.hni().to_string()),
            ("x-fb-net-hni".to_string(), state.carrier.hni().to_string()),
            (
                "x-fb-rmd".to_string(),
                "cached=0;state=NO_MATCH".to_string(),
            ),
            (
                "x-fb-request-analytics-tags".to_string(),
                "unknown".to_string(),
            ),
            (
                "authorization".to_string(),
                format!(
                    "OAuth {}",
                    &state
                        .session
                        .access_token
                        .as_ref()
                        .unwrap_or(&"null".to_string())
                ),
            ),
        ]);
        if let Some(device_group) = &state.device.device_group {
            headers.insert("x-fb-device-group".to_string(), device_group.to_string());
        };
        (&headers).try_into().unwrap()
    }
    fn params(&self, state: &State) -> HashMap<&str, &str> {
        HashMap::from([
            ("locale", state.device.language),
            ("client_country_code", state.device.country_code),
        ])
    }
    // def format(self, req: dict[str, str], sign: bool = True, **extra: str) -> str:
    //   req = dict(sorted(req.items()))
    //   if sign:
    //       sig_data = "".join(f"{key}={value}" for key, value in req.items())
    //       sig_data_bytes = (sig_data + self.state.application.client_secret).encode("utf-8")
    //       req["sig"] = hashlib.md5(sig_data_bytes).hexdigest()
    //   if extra:
    //       req.update(extra)
    //   return "&".join(f"{quote(key)}={quote(value)}" for key, value in sorted(req.items()))

    fn format(
        &self,
        state: &State,
        req: HashMap<&str, &str>,
        sign: Option<bool>,
        extra: Option<HashMap<&str, &str>>,
    ) -> String {
        let mut req: Vec<(&str, &str)> = req.into_iter().collect();
        req.sort_by(|x, y| x.0.cmp(&y.0));
        let sign = sign.unwrap_or(true);
        if sign {
            let sig_data = req
                .iter()
                .map(|(key, value)| format!("{}={}", key, value))
                .collect::<Vec<_>>()
                .join("");
            let sig_data_bytes = (sig_data + state.application.client_secret).as_bytes();
            // TODO: finish this
        }
        if let Some(extra) = extra {
            req.extend(extra.into_iter());
        }
        req.iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<_>>()
            .join("&")
    }
    //   if (
    //     resp.headers.get("content-encoding") == "x-fb-dz"
    //     and resp.headers.get("x-fb-dz-dict") == "1"
    //     and not getattr(resp, "_zstd_decompressed", None)
    // ):
    //     compressed = await resp.read()
    //     resp._body = zstd_decomp.decompress(compressed)
    //     self.log.trace(
    //         f"Decompressed {len(compressed)} bytes of zstd "
    //         f"into {len(resp._body)} bytes of (hopefully) JSON"
    //     )
    //     setattr(resp, "_zstd_decompressed", True)
    async fn decompress_zstd(&self, response: &mut DecompressableResponse) {
        let headers = response.response.headers();
        if headers.get("content-encoding")
            == Some(&reqwest::header::HeaderValue::from_static("x-fb-dz"))
            && headers.get("x-fb-dz-dict") == Some(&reqwest::header::HeaderValue::from_static("1"))
            && !response.decompressed
        {
            let bytes_result = response.response.bytes().await;
            if let Ok(bytes) = bytes_result {
                let body: &[u8] = &bytes;
                response.data =
                    zstd::Decoder::with_prepared_dictionary(body, &self.decoder_dict).unwrap();
                response.decompressed = true;
            }
        }
    }
}

mod login;
