import boto3
from typing import Optional


def session(region: Optional[str] = None, profile: Optional[str] = None):
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def client(service: str, region: Optional[str] = None, profile: Optional[str] = None):
    return session(region=region, profile=profile).client(service)
