mod api;

#[cfg(test)]
mod tests {
    use super::api::API;

    #[tokio::test]
    async fn login_test() {
        let mut api = API::new();
        api.state.generate();
        api.http.mobile_config_sessionless(&mut api.state).await;
        // Ok(())
    }
}
