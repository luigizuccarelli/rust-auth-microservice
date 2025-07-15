use custom_logger as log;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::AUTHORIZATION;
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::time::{Duration, UNIX_EPOCH};
use url::Url;

use crate::MAP_LOOKUP;

#[derive(Deserialize, Serialize, Debug)]
struct Claims {
    custom_claim: String,
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
}

#[derive(Debug, Serialize)]
struct AuthBody {
    access_token: String,
    token_type: String,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    message: String,
    status: String,
}

impl AuthBody {
    fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
        }
    }
}

// custom JWT auth service, handling two different routes
pub async fn auth_token_service(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut response = Response::new(Full::default());
    match (req.method(), req.uri().path()) {
        // get a JWT token route.
        (&Method::POST, "/token") => {
            let uri_string = req.uri().to_string();
            let request_url = Url::parse(&uri_string).unwrap();
            let params_hm: HashMap<_, _> = request_url.query_pairs().into_owned().collect();
            if params_hm.get("user").is_none() || params_hm.get("session-id").is_none() {
                let validate_response = AuthResponse {
                    status: "bad request".to_string(),
                    message: "request parameters : user and session-id are missing or incorrrect"
                        .to_string(),
                };
                *response.status_mut() = StatusCode::BAD_REQUEST;
                *response.body_mut() =
                    Full::from(serde_json::to_string(&validate_response).unwrap());
            } else {
                let user = params_hm.get("user").unwrap();
                let session_id = params_hm.get("session-id").unwrap();
                // do db lookup
                log::debug!("{user} {session_id}");
                // set up hypertls
                let https = HttpsConnector::new();
                let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(https);
                let hm = MAP_LOOKUP.lock().unwrap().clone();
                let client_response = client
                    .get(
                        format!("{}/user={}", hm.unwrap().get("user_api_url").unwrap(), user)
                            .parse()
                            .unwrap(),
                    )
                    .await;
                let res = client_response.unwrap();
                let user_data = res.body();
                log::debug!("result user api call {:?}", user_data);

                // do a lookup on the db for user and sessionid
                let time_exp = std::time::SystemTime::now()
                    .checked_add(Duration::from_secs(3600))
                    .unwrap()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let c = Claims {
                    custom_claim: "user".to_owned(),
                    iss: "https://samcopai.com".to_owned(),
                    sub: "system auth claim".to_owned(),
                    exp: time_exp,
                    aud: "samcopai".to_owned(),
                };

                let header = jsonwebtoken::Header::default();
                let jwt_secret = match env::var("JWT_SECRET") {
                    Ok(var) => var,
                    Err(_) => "secret".to_string(),
                };
                let secret = jsonwebtoken::EncodingKey::from_secret(jwt_secret.as_bytes());
                let token = jsonwebtoken::encode(&header, &c, &secret).unwrap();
                let auth_body = AuthBody::new(token);
                *response.body_mut() = Full::from(serde_json::to_string(&auth_body).unwrap());
            }
        }
        // validate a JWT token route.
        (&Method::POST, "/validate") => {
            match req.headers().get(AUTHORIZATION) {
                Some(token) => {
                    let jwt = token.to_str().unwrap().split(" ").nth(1).unwrap();
                    let mut validation =
                        jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
                    validation.set_audience(&vec!["samcopai"]);
                    validation.set_issuer(&vec!["https://samcopai.com"]);
                    validation.set_required_spec_claims(&["iss,aud,exp,sub"]);
                    let jwt_secret = match env::var("JWT_SECRET") {
                        Ok(var) => var,
                        Err(_) => "secret".to_string(),
                    };
                    let secret = jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes());
                    // decode token
                    let res = jsonwebtoken::decode::<Claims>(jwt, &secret, &validation);
                    if res.is_err() {
                        let validate_response = AuthResponse {
                            status: "forbidden".to_string(),
                            message: format!("error: {}", res.as_ref().err().unwrap()),
                        };
                        *response.status_mut() = StatusCode::FORBIDDEN;
                        *response.body_mut() =
                            Full::from(serde_json::to_string(&validate_response).unwrap());
                    } else {
                        let validate_response = AuthResponse {
                            status: "validated".to_string(),
                            message: "token succesfully validated".to_string(),
                        };
                        log::debug!("res {:?}", res);
                        *response.body_mut() =
                            Full::from(serde_json::to_string(&validate_response).unwrap());
                    }
                }
                None => {
                    let validate_response = AuthResponse {
                        status: "unauthorized".to_string(),
                        message: "error: bearer auth token missing".to_string(),
                    };
                    *response.status_mut() = StatusCode::UNAUTHORIZED;
                    *response.body_mut() =
                        Full::from(serde_json::to_string(&validate_response).unwrap());
                }
            }
        }
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    Ok(response)
}
