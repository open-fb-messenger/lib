mod api;

#[cfg(test)]
mod tests {
    use super::api::http::login::LoginError;
    use super::api::API;
    use dotenv::dotenv;
    use std::env;
    use std::io::{stdin, stdout, Write};

    #[tokio::test]
    async fn login() {
        dotenv().ok();
        let mut api = API::new();
        api.state.generate(Some([
            0, 2, 3, 5, 1, 2, 3, 43, 5, 5, 3, 12, 33, 1, 3, 3, 0, 2, 3, 5, 1, 2, 3, 43, 5, 5, 3,
            12, 33, 1, 3, 3,
        ]));
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
        println!("{:?}", api.state.session.uid);
        match result {
            Ok(_) => {
                println!("Login successful {:?}", result);
            }
            Err(e) => match e {
                LoginError::Requires2FA => {
                    let mut s = String::new();
                    println!("2FA is required, please enter the code");
                    let _ = stdout().flush();
                    stdin()
                        .read_line(&mut s)
                        .expect("Did not enter a correct string");
                    let code = s.trim();
                    let result = api
                        .http
                        .login_2fa(
                            &mut api.state,
                            env::var("EMAIL").expect("$EMAIL is not set"),
                            code.to_string(),
                        )
                        .await;
                    println!("{:?}", api.state.session.uid);

                    println!("{:?}", result);
                    api.http
                        .check_approved_machine(&mut api.state)
                        .await
                        .unwrap();
                }
                _ => println!("Login failed {:?}", e),
            },
        }
    }
}
