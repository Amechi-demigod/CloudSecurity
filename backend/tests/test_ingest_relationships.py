"""Duplicate edges reported by a connector in one scan must not break ingest."""
from sqlalchemy import select

from app.connectors.base import AssetRecord, CollectionResult, RelationshipRecord
from app.models import Relationship
from app.services.ingest import ingest_collection

IDENT = "/subscriptions/s1/resourcegroups/rg/providers/microsoft.managedidentity/userassignedidentities/id1"
VAULT = "/subscriptions/s1/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1"


def _result(*rels: RelationshipRecord) -> CollectionResult:
    return CollectionResult(
        assets=[
            AssetRecord(id=IDENT, name="id1", type="identity", subscription_id="s1"),
            AssetRecord(id=VAULT, name="kv1", type="key_vault", subscription_id="s1"),
        ],
        relationships=list(rels),
    )


def test_duplicate_edges_in_one_scan_are_merged(session):
    ingest_collection(session, _result(
        RelationshipRecord(IDENT, VAULT, "has_access", {"role": "Key Vault Secrets User"}),
        RelationshipRecord(IDENT, VAULT, "has_access", {"role": "Key Vault Administrator"}),
        RelationshipRecord(IDENT, VAULT, "has_access", {"role": "Key Vault Secrets User"}),
    ), "azure")

    rels = list(session.scalars(select(Relationship)))
    assert len(rels) == 1
    assert rels[0].properties["role"] == "Key Vault Secrets User"
    assert rels[0].properties["roles"] == ["Key Vault Administrator", "Key Vault Secrets User"]


def test_rescan_with_duplicates_keeps_single_edge(session):
    dup = (
        RelationshipRecord(IDENT, VAULT, "has_access", {"role": "Key Vault Secrets User"}),
        RelationshipRecord(IDENT, VAULT, "has_access", {"role": "Key Vault Secrets User"}),
    )
    ingest_collection(session, _result(*dup), "azure")
    ingest_collection(session, _result(*dup), "azure")

    assert len(list(session.scalars(select(Relationship)))) == 1
