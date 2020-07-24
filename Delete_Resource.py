"""
Purpose :
    This script is used to Delete the Resources that are automatically 
    created using the script mentioned in the blog - 
    https://scripting4ever.wordpress.com/2020/05/19/automating-s3-bucket-creation-with-access-logging-and-enabling-the-analysis-in-aws-athena/

Method :
    There are 2 ways of deleting the resources
    1. Deleting all resources for all projects
    2. Deleting resources for a particular project
Developer : K.Janarthanan
Date: 18/7/2020
"""

import boto3
import logging
import sys
import os
import time
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s:%(levelname)s:%(message)s")


def select_region():

    os.environ["AWS_DEFAULT_REGION"] = "ap-southeast-1"

    regions = boto3.client("ec2")
    response = regions.describe_regions()

    print("\n--------------\nAWS S3 Region :\n--------------\n")

    region_key = {}
    for i in range(len(response["Regions"])):
        region_key[i] = response["Regions"][i]["RegionName"]
        print("[" + str(i) + "] " + response["Regions"][i]["RegionName"])

    region_num = int(input("\nInput the Region Number : "))

    if region_num not in region_key.keys():
        print("Region Key is invalid. Script existing")
        sys.exit()

    else:
        os.environ["AWS_DEFAULT_REGION"] = region_key[region_num]
        return region_key[region_num]


def delete_bucket(bucket_name):
    """
    This function is used to delete bucket with its contents
    """
    try:
        logging.info("Going to delete the bucket : " + bucket_name)

        s3 = boto3.resource("s3")
        bucket = s3.Bucket(bucket_name)
        bucket.objects.delete()

        bucket.delete()
        logging.info("Deleted the bucket")

    except ClientError as e:
        logging.error(str(e))


def delete_workgroup(workgroup_name):
    try:
        logging.info("Going to delete Athena workgroup : " + workgroup_name)

        client = boto3.client("athena")

        response_wg_delete = client.delete_work_group(
            WorkGroup=workgroup_name, RecursiveDeleteOption=True
        )

        if response_wg_delete["ResponseMetadata"]["HTTPStatusCode"] != 200:
            raise Exception(
                "Status code from deletion of Athena Workgroup"
                + workgroup_name
                + " is not 200"
            )
        else:
            logging.info(
                "Athena Workgroup " + workgroup_name + " is deleted successfully"
            )

    except ClientError as e:
        logging.error(str(e))


def delete_database(bucket_name, athena_bucket):
    try:
        logging.info("Going to delete Database and Table")
        client = boto3.client("athena")

        database = ("athena_analysis_" + bucket_name).replace("-", "_")
        table = ("log_" + bucket_name).replace("-", "_")

        logging.info("Table " + table + " is going to be deleted")

        response_delete_db = client.start_query_execution(
            QueryString="drop table " + table + ";",
            QueryExecutionContext={"Database": database},
            ResultConfiguration={"OutputLocation": "s3://" + athena_bucket},
        )

        if response_delete_db["ResponseMetadata"]["HTTPStatusCode"] != 200:
            raise Exception(
                "Status code from deletion of Athena Table " + table + " is not 200"
            )
        else:
            logging.info("Athena Table " + table + " is deleted successfully")

        logging.info("Database " + database + " is going to be deleted")

        response_delete_db = client.start_query_execution(
            QueryString="drop database " + database + ";",
            QueryExecutionContext={"Database": database},
            ResultConfiguration={"OutputLocation": "s3://" + athena_bucket},
        )

        if response_delete_db["ResponseMetadata"]["HTTPStatusCode"] != 200:
            raise Exception(
                "Status code from deletion of Athena Database "
                + database
                + " is not 200"
            )
        else:
            logging.info("Athena Table " + database + " is deleted successfully")

        # Sleep (Delete logs will be published to Athena logging Bucket, therefore deleting immediately Bucket cause error )
        logging.info(
            "Delete logs will be published to Athena logging Bucket, therefore deleting immediately Bucket cause error. Sleep 5 Mins"
        )
        time.sleep(300)

    except ClientError as e:
        logging.error(str(e))


"""
Main Program
"""

print(
    """
Warninig - This script is used to delete AWS resources created already

"""
)

# Region select
region = select_region()

print(
    """

    There are 2 ways of deleting the resources
        1. Deleting all resources for all projects
        2. Deleting resources for a particular project

    """
)

option = int(input("\nPlease select your option [1/2] : "))

if (option == 1) or (option == 2):

    if option == 2:
        bucket_name = input("\nPlease provide the source bucket name : ")

        try:

            client = boto3.client("s3")
            response = client.list_buckets()

            # Deleting relavant Athena Log and Access Log Buckets
            if response["ResponseMetadata"]["HTTPStatusCode"] == 200:

                regional_buckets = []

                for buckets in response["Buckets"]:
                    if (
                        client.get_bucket_location(Bucket=buckets["Name"])[
                            "LocationConstraint"
                        ]
                        == region
                    ):
                        regional_buckets.append(buckets)

                if len(regional_buckets) == 0:
                    logging.warning("No any buckets found in this region")
                    sys.exit()

                for item in regional_buckets:

                    pattern1 = bucket_name + "-accesslog"
                    pattern2 = bucket_name + "-athena"

                    # Deleting Source Bucket
                    if bucket_name == item["Name"]:
                        delete_bucket(bucket_name)

                    elif pattern1 in item["Name"]:
                        delete_bucket(item["Name"])

                    elif pattern2 in item["Name"]:
                        athena_bucket = item["Name"]
                        delete_database(bucket_name, athena_bucket)
                        delete_workgroup(bucket_name)

                        delete_bucket(item["Name"])

            else:
                raise Exception(
                    "Response Code is not 200. Therefore abondoning the deletion process "
                )

        except Exception as e:
            logging.error(str(e))

    # Option 1
    else:
        try:
            client = boto3.client("s3")
            response = client.list_buckets()

            must_delete = []
            not_matching = []

            # Deleting relavant Athena Log and Access Log Buckets
            if response["ResponseMetadata"]["HTTPStatusCode"] == 200:

                regional_buckets = []

                for buckets in response["Buckets"]:
                    if (
                        client.get_bucket_location(Bucket=buckets["Name"])[
                            "LocationConstraint"
                        ]
                        == region
                    ):
                        regional_buckets.append(buckets)

                if len(regional_buckets) == 0:
                    logging.warning("No any buckets found in this region")
                    sys.exit()

                for item in regional_buckets:

                    pattern1 = "-accesslog"
                    pattern2 = "-athena"

                    if pattern1 in item["Name"]:
                        must_delete.append(item["Name"])

                    elif pattern2 in item["Name"]:
                        athena_bucket = item["Name"]
                        source_bucket = str(item["Name"]).split("-athena")[0]
                        delete_database(source_bucket, athena_bucket)
                        delete_workgroup(source_bucket)

                        must_delete.append(item["Name"])

                    else:
                        not_matching.append(item["Name"])

                if len(not_matching) == 0:

                    if len(must_delete) != 0:
                        for item in must_delete:
                            delete_bucket(item)
                    else:
                        logging.info("Nothing to delete")

                else:

                    for single_bucket in not_matching:

                        flag = 0

                        for item in must_delete:
                            pattern1 = single_bucket + "-accesslog"
                            pattern2 = single_bucket + "-athena"

                            if pattern1 in item:
                                delete_bucket(item)
                                must_delete.remove(item)
                                flag = 1

                            if pattern2 in item:
                                athena_bucket = item
                                delete_database(single_bucket, item)
                                delete_workgroup(single_bucket)

                                delete_bucket(item)
                                must_delete.remove(item)
                                flag = 1

                        if flag == 1:
                            delete_bucket(single_bucket)

                    if len(must_delete) != 0:
                        for remaining_item in must_delete:
                            delete_bucket(remaining_item)

            else:
                raise Exception(
                    "Response Code is not 200. Therefore abondoning the deletion process "
                )

        except Exception as e:
            logging.error(str(e))

    logging.info("Script Completed")

else:
    print("Only option '1' or '2' allowed")
    sys.exit()
