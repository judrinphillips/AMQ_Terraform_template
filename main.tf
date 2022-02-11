
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.70.0"
    }
  }

  required_version = ">= 0.14.9"
}

variable "name" {
  type = string
  default = "project_code"
}

variable "tags" {
  type = map(string)
}

variable "vpc_id" {
  type = string
}

variable "region" {
  type = string
  default = "eu-west-2"
}

variable "public_subnet" {
  type = string

}

variable "Amazon_MQBroker_AdminUsername" {
  type = string

}

variable "Amazon_MQBroker_ApplicationUsername" {
  type = string
}

variable "AmqSubnets" {
  type = string
}

variable "AmqSubnetCidr" {
  type = string
}

variable "ManagementVPC_Cidr" {
  type = string
}

module "path" {
  source = "config2_base64_encode.txt"

}

variable "config2_base64_encode" {
  type = file
  default = "config2_base64_encode.txt"
}








variable "Environmentinstance" {
  type = string
}



module "AMQ_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 4"

  name        = "AMQ_Security_Group"
  description = "AMQ_Security_group"
  vpc_id      =  var.vpc_id


ingress_with_cidr_blocks = [
    {
      from_port = 8162
      to_port = 8162
      protocol = "tcp"


      cidr_blocks = var.ManagementVPC_Cidr

      from_port = 61617
      to_port = 61617
      protocol = "tcp"
      cidr_blocks = var.ManagementVPC_Cidr

      from_port = 5671
      to_port = 5671
      protocol = "tcp"
      cidr_blocks = var.ManagementVPC_Cidr

      from_port = 61614
      to_port = 61614
      protocol = "tcp"
      cidr_blocks = var.ManagementVPC_Cidr

      from_port = 8883
      to_port = 8883
      protocol = "tcp"
      cidr_blocks = var.ManagementVPC_Cidr


      from_port = 61617
      to_port = 61617
      protocol = "tcp"
      cidr_blocks = "${element(split(",",var.AmqSubnetCidr ),0 )}"

      from_port= 61617
      to_port = 61617
      protocol= "tcp"
      cidr_blocks = "${element(split(",",var.AmqSubnetCidr ),1 )}"

      from_port= 61617
      to_port= 61617
      protocol= "tcp"
      cidr_blocks = "${element(split(",",var.AmqSubnetCidr ),2 )}"

      from_port= 8162
      to_port= 8162
      protocol= "tcp"

      cidr_blocks = "${element(split(",",var.AmqSubnetCidr ),0 )}"

      from_port= 8162
      to_port= 8162
      protocol= "tcp"

      cidr_blocks = "${element(split(",",var.AmqSubnetCidr ),1 )}"

      from_port= 8162
      to_port= 8162
      protocol= "tcp"

      cidr_blocks = "${element(split(",",var.AmqSubnetCidr ),3 )}"








    }
  ]

}

#Broker 1

resource "aws_mq_broker" "brokerNode1" {
  broker_name         = "brokerNode1"
  engine_type         = "ActiveMQ"
  engine_version      = "5.15.9"
  host_instance_type  = "mq.t2.micro"
  publicly_accessible = false
  security_groups     = [module.AMQ_security_group]
  subnet_ids          = "${element(split(",",var.AmqSubnets),0 )}"
  logs {
    audit   = "true"
    general = "true"
  }
  user {
    password       = module.AMQ_Admin_random_password
    username       = var.Amazon_MQBroker_AdminUsername
    console_access = alltrue()
    groups         = [admin]
  }
  user {
    password = module.AMQ_Application_random_password
    username = var.Amazon_MQBroker_ApplicationUsername
    console_access = false
  }
}

#Broker2
resource "aws_mq_broker" "brokerNode2" {
  broker_name        = "brokerNode2"
  engine_type        = "ActiveMQ"
  engine_version     = "5.15.9"
  host_instance_type = "mq.t2.micro"
  publicly_accessible = false
  security_groups = [module.AMQ_security_group]
  subnet_ids = "${element(split(",",var.AmqSubnets),1 )}"
  user {
    password = module.AMQ_Admin_random_password
    username = var.Amazon_MQBroker_AdminUsername
    console_access = alltrue()
    groups = [admin]
  }
  user {
    password = module.AMQ_Application_random_password
    username = var.Amazon_MQBroker_ApplicationUsername
    console_access = false
    groups = [application]
  }
}

#Broker3
resource "aws_mq_broker" "brokerNode3" {
  broker_name        = "brokerNode3"
  engine_type        = "ActiveMQ"
  engine_version     = "5.15.9"
  host_instance_type = "m2.t2.micro"
  publicly_accessible = false
  security_groups = [module.AMQ_security_group]
  subnet_ids = "${element(split(",",var.AmqSubnets),2 )}"
  user {
    password = module.AMQ_Admin_random_password
    username = var.Amazon_MQBroker_AdminUsername
    console_access = alltrue()
    groups = [admin]
  }
  user {
    password = module.AMQ_Application_random_password
    username = var.Amazon_MQBroker_ApplicationUsername
    console_access = false
    groups = [application]
  }
}



module "AMQ_Admin_random_password" {
  source                  = "git::https://github.com/rhythmictech/terraform-aws-secretsmanager-secret"
  name_prefix             = var.Amazon_MQBroker_AdminUsername
  description             = "AMQ Broker password"

  length                  = 20
  override_special        = "@#$%^*()-=_+[]{};<>?,./"
}
module "AMQ_Application_random_password" {
  source           = "git::https://github.com/rhythmictech/terraform-aws-secretsmanager-secret"
  name_prefix      = var.Amazon_MQBroker_ApplicationUsername
  description      = "AMQ Broker Application password"
  length           = 20
  override_special = "@#$%^*()-=_+[]{};<>?,./"
}
#Configuration 1





module "nlb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 6.0"

  name = join [(var.name )]-[(var.Environmentinstance)]-nlb

  load_balancer_type = "network"

  vpc_id  = var.vpc_id
  subnets = [
    "${element(split(",",var.AmqSubnets),0 )}, ${element(split(",",var.AmqSubnets),1 )},${element(split(",",var.AmqSubnets),0 )}"
  ]

  access_logs = {
    bucket = "my-nlb-logs"

  }
}

resource "aws_lb_target_group" "AMQ_Network_loadbalancer_target" {
 name = join [(var.name )]-[(var.Environmentinstance)]-nlb
 health_check {healthy_threshold = count,unhealthy_threshold = count,port = "8162",protocol = "tcp"}
 port = 8167
 protocol = tcp
 count = 5
target_type = cidrhost(lookup(element(0 )1, )2, )

vpc_id = var.vpc_id


}

resource "aws_lb_listener" "AMQ_Networlloadbalance_listner" {
  load_balancer_arn = module.nlb
  default_action {
    forward {
      target_group {
        arn = aws_lb_target_group.AMQ_Network_loadbalancer_target
      }
    }
    type = "network"
  }
}
resource "aws_mq_configuration" "config1" {
  data           = ""
  engine_type    = ""
  engine_version = ""
  name           = ""
}



resource "aws_mq_configuration" "config2" {
  data           = file(filebase64(var.config2_base64_encode)element(lookup(0,1 )lookup(Broker1,OpenWireEndpoints ),
  "username=var.Amazon_MQBroker_AdminUsername" filebase64() ))
  engine_type    = ACTIVEMQ
  engine_version = 5.15.14
  name           = "BrokerConfig2"


}








