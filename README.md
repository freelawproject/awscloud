# awscloud
The combined repo for Free Law Project's AWS Cloud resources.

awscloud is an open source repository. It was built for use with Courtlistener.com.

Its main goal is to standardize AWS deployments and resource management.
It includes mechanisms to build Lambda functions and test locally, utilizing the [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html).

Further development is intended and all contributors, corrections and additions are welcome.

## Quickstart

The Lambda functions are written in Rust as members of a Cargo workspace. Build and test them with the standard Cargo
tooling:

```bash
cargo build
cargo test
```

Deployments are packaged with the AWS SAM CLI, which builds the Rust functions
via [cargo-lambda](https://www.cargo-lambda.info/). Install both before deploying.

### Resources

1. recap_email - Email routing for RECAP docket updates. See
   [recap_email/](recap_email/).

## Deployment

Before deploying to AWS, you should setup a profile for free-law-project or the test environment you're using.

Then build with SAM (which invokes cargo-lambda) and deploy with the profile environment variable:

```bash
sam build
AWS_PROFILE=free-law-project sam deploy --guided
```

This will guide you through the deployment the first time you run it. It will then save a `samconfig.toml` file with the
deployment configuration for subsequent `sam deploy` runs.

### Local testing

Invoke a function locally against one of the sample events with the SAM CLI:

```bash
sam build
sam local invoke RecapEmailFunction --env-vars env.json --event recap_email/events/ses.json
```

`env.json` contains the default configuration for running against a local CourtListener. If you are testing another
configuration, use a separate environment file.

## License

This repository is available under the permissive BSD license, making it easy and safe to incorporate in your own libraries.

Pull and feature requests welcome. Online editing in GitHub is possible (and easy!)
