import boto3
import time

iam = boto3.client("iam")
sts = boto3.client("sts")

TEST_USER = "cloudtrail-test-user"

def create_access_key():
    print("[+] Creating access key")
    iam.create_access_key(UserName=TEST_USER)

def attach_admin_policy():
    print("[+] Attaching AdministratorAccess")
    iam.attach_user_policy(
        UserName=TEST_USER,
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )

def simulate_login():
    print("[+] Simulating auth call")
    sts.get_caller_identity()

if __name__ == "__main__":
    create_access_key()
    time.sleep(5)

    attach_admin_policy()
    time.sleep(5)

    simulate_login()
