# ibc-demo-cloudfront-2019

This demo provides a DASH player streaming live video using AWS Media Services (MediaLive & MediaPackage), delivered by Amazon CloudFront, and personilized using AWS Lambda@Edge and Amazon Cognito. 

Instructions for deploying in us-east-1.

First, run the below commands:

npm install

npm run build

sam build 

sam package --output-template-file packaged.yaml --s3-bucket <YOUR BUCKET NAME> --region us-east-1
  
sam deploy --template-file packaged.yaml --stack-name <YOUR STACK NAME> --capabilities CAPABILITY_IAM --region us-east-1

Then, go to the created cognito user pool and add a user gourp called premium, then create two users, with one of them in the premium group.
