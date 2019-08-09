npm install
npm run build
sam build 
sam package --output-template-file packaged.yaml --s3-bucket achrsouk-artifacts-bucket --region us-east-1
sam deploy --template-file packaged.yaml --stack-name ibc-demo-cloudfront-2019 --capabilities CAPABILITY_IAM --region us-east-1

