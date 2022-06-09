use rand::{distributions::Slice, thread_rng, Rng};
use uuid::Uuid;
pub struct Device {
    pub manufacturer: &'static str,
    pub builder: &'static str,
    pub name: &'static str,
    pub software: &'static str,
    pub architecture: &'static str,
    pub dimensions: &'static str,
    pub user_agent: &'static str,
    pub connection_type: &'static str,
    pub connection_quality: &'static str,
    pub language: &'static str,
    pub country_code: &'static str,
    pub uuid: Option<String>,
    pub fdid: Option<String>,
    pub adid: Option<String>,
    pub device_group: Option<String>,
}
impl Device {
    pub fn new() -> Device {
        Device {
            manufacturer: "Google",
            builder: "google",
            name: "Pixel 3",
            software: "11",
            architecture: "arm64-v8a:null",
            dimensions: "{density=2.75,width=1080,height=2028}",
            user_agent: "Dalvik/2.1.0 (Linux; U; Android 11; Pixel 3 Build/RQ3A.211001.001)",
            connection_type: "WIFI",
            connection_quality: "EXCELLENT",
            language: "en_US",
            country_code: "US",
            adid: None,
            uuid: None,
            fdid: None,
            device_group: None,
        }
    }

    fn net_iface(&self) -> &str {
        if self.connection_type == "WIFI" {
            return "Wifi";
        } else if self.connection_type == "MOBILE.LTE" {
            return "Cell";
        } else {
            return "Unknown";
        }
    }
}
pub struct Application {
    pub name: &'static str,
    pub version: &'static str,
    pub id: &'static str,
    pub locale: &'static str,
    pub build: i32,
    pub version_id: i64,
    pub client_id: &'static str,
    pub client_secret: &'static str,
}
impl Application {
    pub fn new() -> Application {
        Application {
            name: "Orca-Android",
            version: "346.0.0.7.117",
            id: "com.facebook.orca",
            locale: "en_US",
            build: 348143456,
            version_id: 4663247527104165,
            client_id: "256002347743983",
            client_secret: "374e60f8b9bb6b8cbb30f78030438895",
        }
    }
    pub fn access_token(&self) -> String {
        format!("{}|{}", self.client_id, self.client_secret)
    }
}

pub struct Carrier {
    pub name: &'static str,
    pub mcc: u16,
    pub mnc: u16,
}
impl Carrier {
    pub fn new() -> Carrier {
        Carrier {
            name: "AT&T",
            mcc: 310,
            mnc: 410,
        }
    }
    pub fn hni(&self) -> u32 {
        format!("{}{}", self.mcc, self.mnc).parse::<u32>().unwrap()
    }
}

pub struct Session {
    pub access_token: Option<String>,
    pub uid: Option<i32>,
    pub password_encryption_pubkey: Option<String>,
    pub password_encryption_key_id: Option<i32>,
    pub machine_id: Option<String>,
    pub transient_auth_token: Option<String>,
    pub login_first_factor: Option<String>,
    pub region_hint: &'static str,
}
impl Session {
    pub fn new() -> Session {
        Session {
            access_token: None,
            uid: None,
            password_encryption_pubkey: None,
            password_encryption_key_id: None,
            machine_id: None,
            transient_auth_token: None,
            login_first_factor: None,
            region_hint: "ODN",
        }
    }
}
pub struct State {
    pub device: Device,
    pub application: Application,
    pub carrier: Carrier,
    pub session: Session,
}

impl State {
    pub fn new() -> State {
        State {
            device: Device::new(),
            application: Application::new(),
            carrier: Carrier::new(),
            session: Session::new(),
        }
    }
    pub fn generate(&mut self) {
        let hexdigits: Slice<char> = Slice::new(&[
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'A',
            'B', 'C', 'D', 'E', 'F',
        ])
        .unwrap();
        self.device.fdid = Some(Uuid::new_v4().to_string());
        self.device.adid = Some(
            thread_rng()
                .sample_iter(hexdigits)
                .take(16)
                .collect::<String>(),
        );
        self.device.uuid = Some(Uuid::new_v4().to_string());
        self.device.device_group = Some(
            thread_rng()
                .sample_iter(Slice::new(&[7000, 7999]).unwrap())
                .next()
                .unwrap()
                .to_string(),
        );
        // TODO: Carrier randomization https://www.mcc-mnc.com
    }
}
