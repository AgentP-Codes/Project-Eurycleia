# Copyright 2026 AgentP-Codes
# SPDX-License-Identifier: AGPL-3.0-only
"""Connectors: how the vault reads from (and writes to) the systems where company data lives.

A source connector is any callable `key -> dict | None`. A sink is any callable
taking keyword arguments. The classes here are ready-made adapters; each one
takes an injectable HTTP transport so it can be tested without network access.
"""

from .base import HttpClient, HttpError, Transport
from .email import SMTPSink
from .files import FolderDocuments, TableFile, read_table
from .gdrive import GoogleDriveConnector
from .rest import RESTConnector, RESTSink
from .saas import (
    GmailSink,
    HubSpotConnector,
    HubSpotSink,
    MongoConnector,
    OutlookMailSink,
    SlackMessageSink,
    StripeCustomerConnector,
    StripeRefundSink,
    XeroConnector,
    ZendeskConnector,
    ZendeskReplySink,
)
from .salesforce import SalesforceConnector, SalesforceSink
from .sharepoint import SharePointConnector
from .sql import SQLConnector, SQLSink

__all__ = [
    "FolderDocuments", "GmailSink", "GoogleDriveConnector", "HttpClient", "HttpError", "HubSpotConnector",
    "HubSpotSink", "MongoConnector", "OutlookMailSink", "RESTConnector", "RESTSink", "SlackMessageSink",
    "StripeCustomerConnector", "StripeRefundSink", "XeroConnector", "ZendeskConnector", "ZendeskReplySink",
    "SMTPSink", "SQLConnector", "SQLSink", "SalesforceConnector", "SalesforceSink", "SharePointConnector",
    "TableFile", "Transport", "read_table",
]
