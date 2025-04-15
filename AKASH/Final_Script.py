import boto3
import time
import base64
import logging

# -------------------- CONFIGURATION --------------------
REGION = 'ap-south-1'
AMI_ID = 'ami-0e35ddab05955cf57'
KEY_NAME = 'akashsridhar'
ZIP_URL = 'https://raw.githubusercontent.com/AKASH8525/new/main/php_registration_app.zip'
DB_NAME = 'userdb'
DB_USER = 'admin'
DB_PASSWORD = 'Admin12345'
SNS_EMAIL = 'akashak052004@gmail.com'
SNS_TOPIC_NAME = 'asg-notifications'

# -------------------- SETUP LOGGING --------------------
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# -------------------- AWS CLIENTS --------------------
ec2 = boto3.client('ec2', region_name=REGION)
rds = boto3.client('rds', region_name=REGION)
elb = boto3.client('elbv2', region_name=REGION)
asg_client = boto3.client('autoscaling', region_name=REGION)
sns_client = boto3.client('sns', region_name=REGION)
# No separate CloudWatch client is needed with target tracking

# -------------------- RESOURCE TRACKING --------------------
resources = {
    'vpc': None,
    'subnets': [],  # [0-1]: Public, [2-3]: Private (EC2), [4-5]: Private (RDS)
    'igw': None,
    'nat_gw': None,
    'security_groups': [],  # [0]: ALB-SG, [1]: EC2-SG, [2]: RDS-SG, [3]: Bastion-SG
    'rds': None,
    'launch_template': None,
    'target_group': None,
    'alb': None,
    'asg': None,
    'bastion_instance': None,
    'sns_topic_arn': None
}

def create_network():
    try:
        logging.info("Creating VPC...")
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        resources['vpc'] = vpc['Vpc']['VpcId']
        ec2.modify_vpc_attribute(VpcId=resources['vpc'], EnableDnsSupport={'Value': True})
        ec2.modify_vpc_attribute(VpcId=resources['vpc'], EnableDnsHostnames={'Value': True})
        ec2.create_tags(Resources=[resources['vpc']], Tags=[{'Key': 'Name', 'Value': 'Main-VPC'}])
        logging.info(f"VPC created with ID: {resources['vpc']}")

        logging.info("Creating Internet Gateway...")
        igw = ec2.create_internet_gateway()
        resources['igw'] = igw['InternetGateway']['InternetGatewayId']
        ec2.attach_internet_gateway(InternetGatewayId=resources['igw'], VpcId=resources['vpc'])
        logging.info(f"Internet Gateway created with ID: {resources['igw']}")

        logging.info("Creating Subnets...")
        subnets = [
            ('10.0.1.0/24', f'{REGION}a', 'public-1'),
            ('10.0.2.0/24', f'{REGION}b', 'public-2'),
            ('10.0.3.0/24', f'{REGION}a', 'private-ec2-1'),
            ('10.0.4.0/24', f'{REGION}b', 'private-ec2-2'),
            ('10.0.5.0/24', f'{REGION}a', 'private-rds-1'),
            ('10.0.6.0/24', f'{REGION}b', 'private-rds-2')
        ]
        for cidr, az, name in subnets:
            subnet = ec2.create_subnet(
                CidrBlock=cidr,
                VpcId=resources['vpc'],
                AvailabilityZone=az,
                TagSpecifications=[{
                    'ResourceType': 'subnet',
                    'Tags': [{'Key': 'Name', 'Value': name}]
                }]
            )
            resources['subnets'].append(subnet['Subnet']['SubnetId'])
            logging.info(f"Subnet {name} created with ID: {subnet['Subnet']['SubnetId']}")

        logging.info("Creating NAT Gateway...")
        eip = ec2.allocate_address(Domain='vpc')
        nat_gw = ec2.create_nat_gateway(
            SubnetId=resources['subnets'][0],
            AllocationId=eip['AllocationId'],
            TagSpecifications=[{
                'ResourceType': 'natgateway',
                'Tags': [{'Key': 'Name', 'Value': 'Main-NAT'}]
            }]
        )
        resources['nat_gw'] = nat_gw['NatGateway']['NatGatewayId']
        ec2.get_waiter('nat_gateway_available').wait(NatGatewayIds=[resources['nat_gw']])
        logging.info(f"NAT Gateway created with ID: {resources['nat_gw']}")

        logging.info("Configuring Route Tables...")
        public_rt = ec2.create_route_table(VpcId=resources['vpc'])['RouteTable']['RouteTableId']
        ec2.create_route(RouteTableId=public_rt, DestinationCidrBlock='0.0.0.0/0', GatewayId=resources['igw'])
        ec2.associate_route_table(RouteTableId=public_rt, SubnetId=resources['subnets'][0])
        ec2.associate_route_table(RouteTableId=public_rt, SubnetId=resources['subnets'][1])

        private_rt = ec2.create_route_table(VpcId=resources['vpc'])['RouteTable']['RouteTableId']
        ec2.create_route(RouteTableId=private_rt, DestinationCidrBlock='0.0.0.0/0', NatGatewayId=resources['nat_gw'])
        for subnet in resources['subnets'][2:4]:
            ec2.associate_route_table(RouteTableId=private_rt, SubnetId=subnet)

        logging.info("Network setup complete!")
    except Exception as e:
        logging.error(f"Network creation failed: {str(e)}")
        exit(1)

def create_security_groups():
    try:
        logging.info("Creating Security Groups...")
        alb_sg = ec2.create_security_group(
            Description='ALB Security Group', GroupName='ALB-SG', VpcId=resources['vpc'],
            TagSpecifications=[{'ResourceType': 'security-group', 'Tags': [{'Key': 'Name', 'Value': 'ALB-SG'}]}]
        )['GroupId']
        ec2.authorize_security_group_ingress(
            GroupId=alb_sg,
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )

        ec2_sg = ec2.create_security_group(
            Description='EC2 Security Group', GroupName='EC2-SG', VpcId=resources['vpc'],
            TagSpecifications=[{'ResourceType': 'security-group', 'Tags': [{'Key': 'Name', 'Value': 'EC2-SG'}]}]
        )['GroupId']
        
        bastion_sg = ec2.create_security_group(
            Description='Bastion Host Security Group', GroupName='Bastion-SG', VpcId=resources['vpc'],
            TagSpecifications=[{'ResourceType': 'security-group', 'Tags': [{'Key': 'Name', 'Value': 'Bastion-SG'}]}]
        )['GroupId']
        ec2.authorize_security_group_ingress(
            GroupId=bastion_sg,
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )

        ec2.authorize_security_group_ingress(
            GroupId=ec2_sg,
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'UserIdGroupPairs': [{'GroupId': alb_sg}]}]
        )
        ec2.authorize_security_group_ingress(
            GroupId=ec2_sg,
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'UserIdGroupPairs': [{'GroupId': bastion_sg}]}]  # Allow SSH from Bastion
        )

        rds_sg = ec2.create_security_group(
            Description='RDS Security Group', GroupName='RDS-SG', VpcId=resources['vpc'],
            TagSpecifications=[{'ResourceType': 'security-group', 'Tags': [{'Key': 'Name', 'Value': 'RDS-SG'}]}]
        )['GroupId']
        ec2.authorize_security_group_ingress(
            GroupId=rds_sg,
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'UserIdGroupPairs': [{'GroupId': ec2_sg}]}]
        )

        resources['security_groups'].extend([alb_sg, ec2_sg, rds_sg, bastion_sg])
        logging.info("All Security Groups created!")
    except Exception as e:
        logging.error(f"Security group creation failed: {str(e)}")
        exit(1)

def create_rds():
    try:
        logging.info("Creating RDS Instance...")
        rds.create_db_subnet_group(
            DBSubnetGroupName='rds-subnet-group',
            DBSubnetGroupDescription='RDS subnet group',
            SubnetIds=resources['subnets'][4:6]
        )
        rds.create_db_instance(
            DBInstanceIdentifier='web-db',
            AllocatedStorage=20,
            DBInstanceClass='db.t3.micro',
            Engine='mysql',
            MasterUsername=DB_USER,
            MasterUserPassword=DB_PASSWORD,
            VpcSecurityGroupIds=[resources['security_groups'][2]],
            DBSubnetGroupName='rds-subnet-group',
            MultiAZ=True,  # Multi-AZ enabled for high availability
            PubliclyAccessible=False,
            DBName=DB_NAME
        )
        resources['rds'] = 'web-db'
        rds.get_waiter('db_instance_available').wait(DBInstanceIdentifier='web-db')
        return rds.describe_db_instances(DBInstanceIdentifier='web-db')['DBInstances'][0]['Endpoint']['Address']
    except Exception as e:
        logging.error(f"RDS creation failed: {str(e)}")
        exit(1)

def create_launch_template(db_endpoint):
    try:
        logging.info("Creating Launch Template...")
        user_data = f'''#!/bin/bash
sudo apt-get update -y
sudo apt-get install -y apache2 php libapache2-mod-php php-mysql unzip wget mysql-client
sudo systemctl start apache2
sudo chown -R www-data:www-data /var/www/html
cd /var/www/html
sudo rm -f index.html
sudo wget {ZIP_URL} -O app.zip
sudo unzip -o app.zip
sudo rm app.zip

sudo bash -c "cat > /var/www/html/dbconfig.php" <<EOL
<?php
\$host = "{db_endpoint}";
\$db  = "{DB_NAME}";
\$user = "{DB_USER}";
\$pass = "{DB_PASSWORD}";

\$conn = new mysqli(\$host, \$user, \$pass, \$db);
if (\$conn->connect_error) {{
    die("Connection failed: " . \$conn->connect_error);
}}
?>
EOL

counter=0
until sudo mysql -h {db_endpoint} -u {DB_USER} -p{DB_PASSWORD} -e "USE {DB_NAME};" 2>/dev/null; do
    if [ $counter -ge 10 ]; then exit 1; fi
    sleep 30
    ((counter++))
done

sudo mysql -h {db_endpoint} -u {DB_USER} -p{DB_PASSWORD} -D {DB_NAME} -e "
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100) UNIQUE,
    password VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);" 2>/dev/null
sudo systemctl restart apache2
'''
        ec2.create_launch_template(
            LaunchTemplateName='php-app-lt',
            LaunchTemplateData={
                'ImageId': AMI_ID,
                'InstanceType': 't2.micro',
                'KeyName': KEY_NAME,
                'SecurityGroupIds': [resources['security_groups'][1]],
                'UserData': base64.b64encode(user_data.encode()).decode(),
                'TagSpecifications': [{
                    'ResourceType': 'instance',
                    'Tags': [{'Key': 'Name', 'Value': 'PHP-App'}]
                }]
            }
        )
        resources['launch_template'] = 'php-app-lt'
        logging.info("Launch Template created.")
    except Exception as e:
        logging.error(f"Launch Template creation failed: {str(e)}")
        exit(1)

def create_alb():
    try:
        logging.info("Creating ALB Resources...")
        tg = elb.create_target_group(
            Name='php-tg', Protocol='HTTP', Port=80, VpcId=resources['vpc'],
            HealthCheckProtocol='HTTP', HealthCheckPath='/register.php',
            HealthyThresholdCount=2, UnhealthyThresholdCount=2
        )
        resources['target_group'] = tg['TargetGroups'][0]['TargetGroupArn']

        alb = elb.create_load_balancer(
            Name='php-alb', Subnets=resources['subnets'][0:2],
            SecurityGroups=[resources['security_groups'][0]], Scheme='internet-facing'
        )['LoadBalancers'][0]
        resources['alb'] = alb['LoadBalancerArn']
        elb.get_waiter('load_balancer_available').wait(LoadBalancerArns=[resources['alb']])

        elb.create_listener(
            LoadBalancerArn=resources['alb'], Protocol='HTTP', Port=80,
            DefaultActions=[{'Type': 'forward', 'TargetGroupArn': resources['target_group']}]
        )
        logging.info("ALB setup complete.")
    except Exception as e:
        logging.error(f"ALB creation failed: {str(e)}")
        exit(1)

def create_sns_topic():
    try:
        logging.info(f"Creating SNS Topic: {SNS_TOPIC_NAME}")
        topic = sns_client.create_topic(Name=SNS_TOPIC_NAME)
        resources['sns_topic_arn'] = topic['TopicArn']
        logging.info(f"SNS Topic created with ARN: {resources['sns_topic_arn']}")

        logging.info(f"Subscribing email {SNS_EMAIL} to SNS Topic...")
        subscription = sns_client.subscribe(
            TopicArn=resources['sns_topic_arn'],
            Protocol='email',
            Endpoint=SNS_EMAIL
        )
        logging.info(f"Subscription initiated. Please check your email ({SNS_EMAIL}) to confirm the subscription.")
    except Exception as e:
        logging.error(f"SNS Topic/Subscription error: {str(e)}")
        exit(1)

def create_asg():
    try:
        logging.info("Creating Auto Scaling Group...")
        asg_client.create_auto_scaling_group(
            AutoScalingGroupName='php-asg',
            LaunchTemplate={'LaunchTemplateName': resources['launch_template'], 'Version': '$Latest'},
            MinSize=2,             # One instance in each private subnet
            MaxSize=4,             # Maximum capacity
            DesiredCapacity=2,     # Start with 2 instances
            VPCZoneIdentifier=','.join(resources['subnets'][2:4]),
            TargetGroupARNs=[resources['target_group']],
            HealthCheckType='ELB',
            HealthCheckGracePeriod=300
        )
        resources['asg'] = 'php-asg'
        
        # Configure SNS notifications for ASG events
        asg_client.put_notification_configuration(
            AutoScalingGroupName=resources['asg'],
            TopicARN=resources['sns_topic_arn'],
            NotificationTypes=[
                'autoscaling:EC2_INSTANCE_LAUNCH',
                'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
                'autoscaling:EC2_INSTANCE_TERMINATE',
                'autoscaling:EC2_INSTANCE_TERMINATE_ERROR'
            ]
        )
        logging.info("ASG created with SNS notifications.")

        # Add a target tracking scaling policy to adjust capacity based on average CPU utilization.
        asg_client.put_scaling_policy(
            AutoScalingGroupName=resources['asg'],
            PolicyName='TargetTrackingPolicy',
            PolicyType='TargetTrackingScaling',
            TargetTrackingConfiguration={
                'PredefinedMetricSpecification': {
                    'PredefinedMetricType': 'ASGAverageCPUUtilization'
                },
                'TargetValue': 50.0,  # Adjust target CPU utilization percentage as needed
                'DisableScaleIn': False
            }
        )
        logging.info("Target tracking scaling policy created.")
    except Exception as e:
        logging.error(f"ASG creation failed: {str(e)}")
        exit(1)

def create_bastion():
    try:
        logging.info("Launching Bastion Host (explicitly assigning public IP)...")
        instance = ec2.run_instances(
            ImageId=AMI_ID,
            InstanceType='t2.micro',
            KeyName=KEY_NAME,
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[{
                'DeviceIndex': 0,
                'SubnetId': resources['subnets'][0],
                'AssociatePublicIpAddress': True,
                'Groups': [resources['security_groups'][3]]
            }],
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{'Key': 'Name', 'Value': 'Bastion-Host'}]
            }]
        )
        instance_id = instance['Instances'][0]['InstanceId']
        resources['bastion_instance'] = instance_id
        ec2.get_waiter('instance_running').wait(InstanceIds=[instance_id])
        response = ec2.describe_instances(InstanceIds=[instance_id])
        public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress', None)
        if public_ip is None:
            logging.warning("Bastion instance did not get a public IP despite explicit assignment.")
        logging.info(f"Bastion Host running: {instance_id} with Public IP: {public_ip}")
        return public_ip
    except Exception as e:
        logging.error(f"Bastion creation failed: {str(e)}")
        exit(1)

def main():
    try:
        create_network()
        create_security_groups()
        db_endpoint = create_rds()
        create_launch_template(db_endpoint)
        create_alb()
        create_sns_topic()
        create_asg()
        bastion_ip = create_bastion()

        alb_dns = elb.describe_load_balancers(LoadBalancerArns=[resources['alb']])['LoadBalancers'][0]['DNSName']
        logging.info(f"\n\nDEPLOYMENT SUCCESSFUL!")
        logging.info(f"Access your registration page at: http://{alb_dns}/register.php")
        logging.info(f"Bastion Host Public IP (for SSH): {bastion_ip}")
        logging.info("NOTE: Check your email and confirm the SNS subscription to receive Auto Scaling notifications.")
    except Exception as e:
        logging.error(f"Deployment failed: {str(e)}")
        exit(1)

if __name__ == '__main__':
    main()
