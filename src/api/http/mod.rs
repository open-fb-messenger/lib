use reqwest::{self, header::HeaderMap, Method};
use std::collections::HashMap;

use super::state::State;
use std::convert::TryInto;
// pub struct DecompressedResponse {
//     pub response: Response,
//     pub decompressed_body: String,
// }
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
        let zstd_dict: &[u8] = include_bytes!("zstd-dict.dat");
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
                "x-fb-connection-quality".to_owned(),
                state.device.connection_quality.to_owned(),
            ),
            (
                "x-fb-connection-type".to_owned(),
                state.device.connection_type.to_owned(),
            ),
            ("user-agent".to_owned(), state.device.user_agent.to_owned()),
            ("x-tigon-is-retry".to_owned(), "False".to_owned()),
            ("x-fb-http-engine".to_owned(), "Liger".to_owned()),
            ("x-fb-client-ip".to_owned(), "True".to_owned()),
            ("x-fb-server-cluster".to_owned(), "True".to_owned()),
            ("x-fb-sim-hni".to_owned(), state.carrier.hni().to_string()),
            ("x-fb-net-hni".to_owned(), state.carrier.hni().to_string()),
            ("x-fb-rmd".to_owned(), "cached=0;state=NO_MATCH".to_owned()),
            (
                "x-fb-request-analytics-tags".to_owned(),
                "unknown".to_owned(),
            ),
            (
                "authorization".to_owned(),
                format!(
                    "OAuth {}",
                    &state
                        .session
                        .access_token
                        .as_ref()
                        .unwrap_or(&"null".to_owned())
                ),
            ),
        ]);
        if let Some(device_group) = &state.device.device_group {
            headers.insert("x-fb-device-group".to_owned(), device_group.to_owned());
        };
        (&headers).try_into().unwrap()
    }
    fn params(&self, state: &State) -> HashMap<&str, &str> {
        HashMap::from([
            ("locale", state.device.language),
            ("client_country_code", state.device.country_code),
        ])
    }

    // TODO: implement tests for this function
    fn format(
        &self,
        state: &State,
        req: HashMap<String, String>,
        sign: bool,
        extra: Option<Vec<(String, String)>>,
    ) -> String {
        let mut req: Vec<(String, String)> = req.into_iter().collect();
        req.sort_by(|x, y| x.0.cmp(&y.0));
        if sign {
            let sig_data = req
                .iter()
                .map(|(key, value)| format!("{}={}", key, value))
                .collect::<Vec<_>>()
                .join("");
            let sig_combined = sig_data + state.application.client_secret;
            let sig_data_copy = sig_combined.as_bytes();
            let signature = format!("{:x}", md5::compute(sig_data_copy));
            for (i, (key, _)) in req.iter().enumerate() {
                if key.to_owned() == "sig" {
                    req.remove(i);
                    break;
                }
            }
            let sig_str = "sig".to_owned();
            req.push((sig_str, signature));
        }
        if let Some(extra) = extra {
            req.extend(extra.into_iter());
        }
        req.sort_by(|x, y| x.0.cmp(&y.0));
        req.iter()
            .map(|(key, value)| {
                format!(
                    "{}={}",
                    urlencoding::encode(key),
                    urlencoding::encode(value)
                )
            })
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
    // TODO: implement this function
    // async fn decompress_zstd(&self, response: Response) {
    //     let headers = response.headers();
    //     if headers.get("content-encoding")
    //         == Some(&reqwest::header::HeaderValue::from_static("x-fb-dz"))
    //         && headers.get("x-fb-dz-dict") == Some(&reqwest::header::HeaderValue::from_static("1"))
    //     {
    //         let bytes_result = response.bytes().await;
    //         if let Ok(bytes) = bytes_result {
    //             let body: &[u8] = &bytes;
    //             DecompressedResponse {
    //                 response,
    //                 decompressed_body: zstd::Decoder::with_prepared_dictionary(
    //                     body,
    //                     &self.decoder_dict,
    //                 )
    //                 .unwrap(),
    //             };
    //         }
    //         // let bytes= bytes_result.unwrap();
    //     }
    // }
}

pub mod login;
