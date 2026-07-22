use lambda_runtime::{
    run,
    service_fn,
    tracing,
    Error,
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let sentry_dsn = std::env::var("SENTRY_DSN").unwrap_or_default();

    let _guard = sentry::init((
        sentry_dsn,
        sentry::ClientOptions {
            // Set traces_sample_rate to 1.0 to capture 100%
            // of transactions for performance monitoring.
            // We recommend adjusting this value in production,
            traces_sample_rate: 1.0,
            ..Default::default()
        },
    ));

    tracing::init_default_subscriber();

    run(service_fn(
        recap_email::app::handler
    ))
    .await
}
