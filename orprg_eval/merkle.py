"""A compact sorted Merkle-set implementation for synthetic revocation proofs.

This is not optimized. It exists to replace flag-only transparency checks with
executable inclusion/non-inclusion proof validation in ORPRG-Eval v3.2.

The public-evaluation root is size-bound: the final committed root includes the
leaf count, so an inclusion proof cannot silently change ``tree_size`` while
keeping the same audit path and internal tree hash.
"""
from __future__ import annotations
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from .canonicalization import canonicalize, digest_obj, sha256_hex
from .crypto import sign_object, verify_signature

EMPTY_TREE_HASH = sha256_hex(b"ORPRG-Eval-v3.2 empty merkle tree")

def _size_bound_root(tree_size: int, tree_hash_hex: str) -> str:
    if tree_size < 0:
        raise ValueError("tree_size must be non-negative")
    return sha256_hex(b"root:" + int(tree_size).to_bytes(8, "big") + bytes.fromhex(tree_hash_hex))

EMPTY_ROOT = _size_bound_root(0, EMPTY_TREE_HASH)

def entry_key(kind: str, identifier: str) -> str:
    return f"{kind}:{identifier}"

def revocation_entry(kind: str, identifier: str, reason: str = "revoked") -> Dict[str, Any]:
    return {"key": entry_key(kind, identifier), "kind": kind, "identifier": identifier, "reason": reason}

def leaf_hash(entry: Mapping[str, Any]) -> str:
    return sha256_hex(b"leaf:" + canonicalize(entry))

def node_hash(left_hex: str, right_hex: str) -> str:
    return sha256_hex(b"node:" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))

def _sorted_entries(entries: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    out = [dict(e) for e in entries]
    seen = set()
    for e in out:
        if "key" not in e:
            raise ValueError("Merkle entries require a key")
        key = str(e["key"])
        if key in seen:
            raise ValueError(f"duplicate Merkle entry key: {key}")
        seen.add(key)
    out.sort(key=lambda e: str(e["key"]))
    return out

def _levels(leaves: Sequence[str]) -> List[List[str]]:
    if not leaves:
        return [[EMPTY_TREE_HASH]]
    levels = [list(leaves)]
    cur = list(leaves)
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else cur[i]
            nxt.append(node_hash(left, right))
        levels.append(nxt)
        cur = nxt
    return levels

def _tree_hash_from_entries(sorted_entries: Sequence[Mapping[str, Any]]) -> str:
    if not sorted_entries:
        return EMPTY_TREE_HASH
    return _levels([leaf_hash(e) for e in sorted_entries])[-1][0]

def merkle_root(entries: Iterable[Mapping[str, Any]]) -> str:
    sorted_entries = _sorted_entries(entries)
    return _size_bound_root(len(sorted_entries), _tree_hash_from_entries(sorted_entries))

def build_inclusion_proof(entries: Iterable[Mapping[str, Any]], key: str) -> Dict[str, Any]:
    sorted_entries = _sorted_entries(entries)
    keys = [str(e["key"]) for e in sorted_entries]
    if key not in keys:
        raise KeyError(key)
    idx = keys.index(key)
    leaves = [leaf_hash(e) for e in sorted_entries]
    levels = _levels(leaves)
    path: List[Dict[str, str]] = []
    pos = idx
    for level in levels[:-1]:
        sib = pos ^ 1
        if sib >= len(level):
            sib = pos
        direction = "left" if sib < pos else "right"
        path.append({"direction": direction, "hash": level[sib]})
        pos //= 2
    return {"proof_type": "inclusion", "entry": sorted_entries[idx], "leaf_index": idx, "tree_size": len(sorted_entries), "audit_path": path}

def _expected_audit_directions(leaf_index: int, tree_size: int) -> List[str]:
    if tree_size <= 0:
        raise ValueError("tree_size must be positive for an inclusion proof")
    if leaf_index < 0 or leaf_index >= tree_size:
        raise ValueError("leaf_index outside tree")
    directions: List[str] = []
    pos = leaf_index
    width = tree_size
    while width > 1:
        sib = pos ^ 1
        if sib >= width:
            sib = pos
        directions.append("left" if sib < pos else "right")
        pos //= 2
        width = (width + 1) // 2
    return directions

def verify_inclusion_proof(proof: Mapping[str, Any], root_hash: str) -> bool:
    try:
        if proof.get("proof_type") != "inclusion":
            return False
        tree_size = int(proof["tree_size"])
        idx = int(proof["leaf_index"])
        expected_directions = _expected_audit_directions(idx, tree_size)
        audit_path = proof.get("audit_path", [])
        if not isinstance(audit_path, list) or len(audit_path) != len(expected_directions):
            return False
        h = leaf_hash(proof["entry"])
        for expected_direction, step in zip(expected_directions, audit_path):
            sibling = str(step["hash"])
            direction = step["direction"]
            if direction != expected_direction:
                return False
            if direction == "left":
                h = node_hash(sibling, h)
            elif direction == "right":
                h = node_hash(h, sibling)
            else:
                return False
        return _size_bound_root(tree_size, h) == root_hash
    except Exception:
        return False

def build_non_inclusion_proof(entries: Iterable[Mapping[str, Any]], key: str) -> Dict[str, Any]:
    sorted_entries = _sorted_entries(entries)
    keys = [str(e["key"]) for e in sorted_entries]
    if key in keys:
        raise ValueError("key is included; cannot build non-inclusion proof")
    prev_key: Optional[str] = None
    next_key: Optional[str] = None
    for k in keys:
        if k < key:
            prev_key = k
        elif k > key and next_key is None:
            next_key = k
            break
    proof: Dict[str, Any] = {"proof_type": "non_inclusion", "target_key": key, "tree_size": len(sorted_entries)}
    if prev_key is not None:
        proof["prev"] = build_inclusion_proof(sorted_entries, prev_key)
    if next_key is not None:
        proof["next"] = build_inclusion_proof(sorted_entries, next_key)
    return proof

def verify_non_inclusion_proof(proof: Mapping[str, Any], root_hash: str) -> bool:
    try:
        if proof.get("proof_type") != "non_inclusion":
            return False
        target = str(proof["target_key"])
        tree_size = int(proof.get("tree_size", 0))
        if tree_size < 0:
            return False
        if tree_size == 0:
            return root_hash == EMPTY_ROOT and proof.get("prev") is None and proof.get("next") is None
        prev_proof = proof.get("prev")
        next_proof = proof.get("next")
        if prev_proof is None and next_proof is None:
            return False
        prev_index: Optional[int] = None
        next_index: Optional[int] = None
        if prev_proof is not None:
            if not verify_inclusion_proof(prev_proof, root_hash):
                return False
            if int(prev_proof.get("tree_size", -1)) != tree_size:
                return False
            prev_index = int(prev_proof["leaf_index"])
            if str(prev_proof["entry"]["key"]) >= target:
                return False
        if next_proof is not None:
            if not verify_inclusion_proof(next_proof, root_hash):
                return False
            if int(next_proof.get("tree_size", -1)) != tree_size:
                return False
            next_index = int(next_proof["leaf_index"])
            if str(next_proof["entry"]["key"]) <= target:
                return False
        if prev_proof is not None and next_proof is not None:
            if str(prev_proof["entry"]["key"]) >= str(next_proof["entry"]["key"]):
                return False
            if prev_index is None or next_index is None or prev_index + 1 != next_index:
                return False
        elif prev_index is not None:
            if prev_index != tree_size - 1:
                return False
        elif next_index is not None:
            if next_index != 0:
                return False
        return True
    except Exception:
        return False

def sign_checkpoint(priv, *, log_id: str, sequence: int, issued_at: str, entries: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    sorted_entries = _sorted_entries(entries)
    body = {
        "log_id": log_id,
        "sequence": sequence,
        "issued_at": issued_at,
        "tree_size": len(sorted_entries),
        "root_hash": merkle_root(sorted_entries),
        "entries_digest": digest_obj({"entries": sorted_entries}),
    }
    return {"checkpoint": body, "signature": sign_object(priv, body)}

def verify_signed_checkpoint(signed_checkpoint: Mapping[str, Any], public_key_b64: str) -> bool:
    try:
        body = signed_checkpoint["checkpoint"]
        sig = signed_checkpoint["signature"]
        return verify_signature(public_key_b64, sig, body)
    except Exception:
        return False
