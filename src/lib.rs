mod api;

#[cfg(test)]
mod tests {
    use super::api::API;
    use std::env;

    #[tokio::test]
    async fn login() {
        let mut api = API::new();
        api.state.generate();
        api.http
            .mobile_config_sessionless(&mut api.state)
            .await
            .unwrap();
        let result = api
            .http
            .login(
                &mut api.state,
                env::var("EMAIL").expect("$EMAIL is not set"),
                env::var("PASSWORD").expect("$PASSWORD is not set"),
                true,
            )
            .await;
        println!("{:?}", result);
    }
}
