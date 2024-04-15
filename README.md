# AWS-TF-Test

This configuration provides reference to provisioning/creation of EC2 instance, vcp, security group, load balancer, target group creation, acm certificate, s3 bucket, iam policy, ingress rule for security group, s3 bucket policy, scmpca certificate authority, load balancer listner.

The above 12 services are needed to deploy an instance to run a webapp with https secure site hosting. In addition to the above deployment, need to have a domain/site purchased, verify route53 DNS entires, create records "A" record to load balancer under hosted domains.

Once EC2 instance is created, login to the instance, and configure the server for your webserver requrirments.

for example:

Installing httpd service

Moving files to /var/www/html folder (if the EC2 instance is Linux)

etc

## Disclaimer:

Please be cautious of pricing for each of the services you are using/consuming, some services are costed 'pay-as-you-go' and few are 'charged on monthly basis'. These are learning fom my experiences and hence wanted to provide the caution before blindly deploying/using/provisioning services for your learning/projects. I highly recommend to refer pricing calculator in aws console under billing and cost management. Also create cost alerts, budget alarms, reports and subscribe to message notification to your mobile number. Dependig upon your project and aws cloud services consumption, do visit the billing page frequently.
