import boto3
from typing import Optional


def get_session(region: Optional[str] = None, profile: Optional[str] = None):
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def get_client(service: str, region: Optional[str] = None, profile: Optional[str] = None):
    return get_session(region=region, profile=profile).client(service)
