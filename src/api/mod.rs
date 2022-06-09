pub mod http;
pub mod state;
// pub mod mqtt;

pub struct API {
    pub state: state::State,
    pub http: http::HTTP,
    // mqtt: mqtt::MQTT,
}
impl API {
    pub fn new() -> API {
        let state = state::State::new();
        API {
            state,
            http: http::HTTP::new(),
            // mqtt: mqtt::MQTT::new(),
        }
    }
}
