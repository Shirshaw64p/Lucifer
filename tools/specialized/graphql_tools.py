"""
tools/specialized/graphql_tools.py — GraphQL security testing.

Introspection query, automatic query generation, and
complexity / batching attack utilities.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from core.scope_guard import check_scope

logger = logging.getLogger(__name__)


# Standard full introspection query
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name description isDeprecated deprecationReason
  }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name description type { ...TypeRef } defaultValue
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name
    ofType { kind name ofType { kind name ofType { kind name
      ofType { kind name }
    }}}
  }}}
}
""".strip()


@dataclass
class GraphQLField:
    name: str
    type_name: str
    args: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class GraphQLType:
    name: str
    kind: str
    fields: List[GraphQLField] = field(default_factory=list)


@dataclass
class IntrospectionResult:
    url: str
    schema_raw: Dict[str, Any] = field(default_factory=dict)
    types: List[GraphQLType] = field(default_factory=list)
    queries: List[str] = field(default_factory=list)
    mutations: List[str] = field(default_factory=list)
    introspection_enabled: bool = False


class GraphQLTools:
    """
    GraphQL security testing suite.

    * ``introspect()``            — run introspection query
    * ``generate_queries()``      — auto-generate queries from schema
    * ``complexity_attack()``     — deeply nested query for DoS testing
    * ``batch_query_attack()``    — batched query abuse
    """

    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    async def introspect(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> IntrospectionResult:
        """Send the full introspection query to *url*."""
        check_scope(url)

        result = IntrospectionResult(url=url)

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                url,
                json={"query": INTROSPECTION_QUERY},
                headers=headers or {},
            )

        if resp.status_code != 200:
            logger.warning("graphql.introspection_failed", extra={"status": resp.status_code})
            return result

        data = resp.json()
        schema = data.get("data", {}).get("__schema")
        if not schema:
            return result

        result.introspection_enabled = True
        result.schema_raw = schema

        # Parse types
        for t in schema.get("types", []):
            name = t.get("name", "")
            if name.startswith("__"):
                continue
            gql_type = GraphQLType(name=name, kind=t.get("kind", ""))
            for f in t.get("fields") or []:
                gql_type.fields.append(
                    GraphQLField(
                        name=f["name"],
                        type_name=self._resolve_type(f.get("type", {})),
                        args=[
                            {"name": a["name"], "type": self._resolve_type(a.get("type", {}))}
                            for a in f.get("args", [])
                        ],
                    )
                )
            result.types.append(gql_type)

        # Extract query/mutation names
        qt = schema.get("queryType", {})
        mt = schema.get("mutationType", {})
        query_type_name = qt.get("name") if qt else None
        mutation_type_name = mt.get("name") if mt else None

        for gtype in result.types:
            if gtype.name == query_type_name:
                result.queries = [f.name for f in gtype.fields]
            elif gtype.name == mutation_type_name:
                result.mutations = [f.name for f in gtype.fields]

        return result

    # ------------------------------------------------------------------
    # Query generation
    # ------------------------------------------------------------------

    def generate_queries(
        self,
        introspection: IntrospectionResult,
        max_depth: int = 2,
    ) -> List[str]:
        """Auto-generate sample queries from the introspection schema."""
        queries: List[str] = []
        type_map = {t.name: t for t in introspection.types}

        for qname in introspection.queries:
            body = self._build_selection(qname, type_map, depth=0, max_depth=max_depth)
            queries.append(f"query {{ {body} }}")

        for mname in introspection.mutations:
            body = self._build_selection(mname, type_map, depth=0, max_depth=max_depth)
            queries.append(f"mutation {{ {body} }}")

        return queries

    def _build_selection(
        self,
        field_name: str,
        type_map: Dict[str, GraphQLType],
        depth: int,
        max_depth: int,
    ) -> str:
        if depth >= max_depth:
            return field_name

        # Find the type that contains this field
        for gtype in type_map.values():
            for f in gtype.fields:
                if f.name == field_name:
                    inner_type = f.type_name
                    inner = type_map.get(inner_type)
                    if inner and inner.fields:
                        children = " ".join(
                            self._build_selection(cf.name, type_map, depth + 1, max_depth)
                            for cf in inner.fields[:5]  # limit breadth
                        )
                        return f"{field_name} {{ {children} }}"
                    return field_name
        return field_name

    # ------------------------------------------------------------------
    # Complexity attack
    # ------------------------------------------------------------------

    async def complexity_attack(
        self,
        url: str,
        field_name: str = "user",
        nested_field: str = "friends",
        depth: int = 10,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate and send a deeply nested query to test for
        query-complexity DoS vulnerabilities.
        """
        check_scope(url)

        inner = field_name
        for _ in range(depth):
            inner = f"{nested_field} {{ {inner} }}"
        query = f"query {{ {inner} }}"

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                url,
                json={"query": query},
                headers=headers or {},
            )

        return {
            "query": query,
            "status": resp.status_code,
            "response_length": len(resp.content),
            "blocked": resp.status_code in (400, 413, 429, 500),
        }

    # ------------------------------------------------------------------
    # Batch query attack
    # ------------------------------------------------------------------

    async def batch_query_attack(
        self,
        url: str,
        query: str,
        count: int = 50,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Send a batched array of identical queries to test for
        batching abuse / rate-limit bypass.
        """
        check_scope(url)

        payload = [{"query": query} for _ in range(count)]

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                url,
                json=payload,
                headers=headers or {},
            )

        return {
            "batch_size": count,
            "status": resp.status_code,
            "response_length": len(resp.content),
            "blocked": resp.status_code in (400, 413, 429, 500),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_type(t: Dict[str, Any]) -> str:
        """Walk the ofType chain to get the leaf type name."""
        while t:
            name = t.get("name")
            if name:
                return name
            t = t.get("ofType", {})
        return "Unknown"
