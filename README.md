# omx-ecr-helper
NIGMS HealthOmics ECR Helper


## IAM Role: CloudFormation Template


```yaml
Description: CloudFormation template for creating a StackSet to config IAM Role
  and Policies for EC2 Termination GH Action
Resources:
  OMXEcrHelperRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: nigms-omx-helper-role
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Federated: !Sub arn:aws:iam::$${AWS::AccountId}:oidc-provider/token.actions.githubusercontent.com
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                token.actions.githubusercontent.com:aud: sts.amazonaws.com
              StringLike:
                token.actions.githubusercontent.com:sub: repo:NIGMS/omx-ecr-helper:*
      Policies:
        - PolicyName: CBIITOmxEcrHelperPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - cloudformation:CreateStack
                  - cloudformation:DescribeStacks
                  - cloudformation:DescribeStackResources
                  - cloudformation:DescribeStackEvents
                  - cloudformation:UpdateStack
                  - cloudformation:DeleteStack
                  - cloudformation:GetTemplate
                  - cloudformation:ValidateTemplate
                  - kms:*
                  - s3:CreateBucket
                  - s3:ListBucket
                  - s3:GetObject
                  - s3:PutObject
                  - s3:DeleteObject
                  - iam:PassRole
                  - sts:AssumeRole
                  - sts:GetCallerIdentity
                  - ecr:GetDownloadUrlForLayer
                  - ecr:BatchGetImage
                  - ecr:BatchCheckLayerAvailability
                  - ecr:PutImage
                  - ecr:InitiateLayerUpload
                  - ecr:UploadLayerPart
                  - ecr:CompleteLayerUpload
                  - lambda:CreateFunction
                  - lambda:InvokeFunction
                  - lambda:UpdateFunctionCode
                  - lambda:GetFunction
                  - lambda:DeleteFunction
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                  - stepfunctions:CreateStateMachine
                  - stepfunctions:StartExecution
                  - stepfunctions:DescribeExecution
                  - stepfunctions:GetExecutionHistory
                  - stepfunctions:DeleteStateMachine
                  - events:PutRule
                  - events:PutTargets
                  - events:DeleteRule
                  - events:RemoveTargets
                Resource: '*'
```
