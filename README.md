# awscloud
The combined repo for Free Law Project's AWS Cloud resources.

awscloud is an open source repository. It was built for use with Courtlistener.com.

Its main goal is to standardize AWS deployments and resource management.
It includes mechanisms to build Lambda functions and test locally, utilizing the [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html).

Further development is intended and all contributors, corrections and additions are welcome.

## Quickstart

Resources are divided into separate directories within this project. This is to support different generations of deployments and workflows.

For each resource, refer to the README.md in the directory.

1. cl (short for courtlistener) - [cl/README.md](cl/README.md)

## Deployment

Before deploying to AWS, you should setup a profile for free-law-project or the test environment you're using.

Then, run the AWS SAM commands with the profile environment variable:

```bash
sam build --use-container
AWS_PROFILE=free-law-project sam deploy --guided
```

This will guide you through the deployment the first time you run it. It will then save a .toml file inside the resource directory with the deployment configuration. For example: cl/samconfig.taml.

## License

This repository is available under the permissive BSD license, making it easy and safe to incorporate in your own libraries.

Pull and feature requests welcome. Online editing in GitHub is possible (and easy!)
