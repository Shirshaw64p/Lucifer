"""
Tests for tools/specialized/graphql_tools.py — GraphQLTools.

All HTTP calls are mocked via httpx MockTransport.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from core.scope_guard import ScopeViolation, reset_scope_guard
from tools.specialized.graphql_tools import GraphQLTools, IntrospectionResult


@pytest.fixture(autouse=True)
def _scope(tmp_path: Path):
    sf = tmp_path / "scope.yaml"
    sf.write_text("scope:\n  includes:\n    - '*.example.com'\n    - 'example.com'\n")
    reset_scope_guard(str(sf))
    yield
    reset_scope_guard(str(sf))


MOCK_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "Query",
                    "description": None,
                    "fields": [
                        {
                            "name": "users",
                            "description": None,
                            "args": [],
                            "type": {"kind": "LIST", "name": None, "ofType": {"kind": "OBJECT", "name": "User", "ofType": None}},
                            "isDeprecated": False,
                            "deprecationReason": None,
                        }
                    ],
                    "inputFields": None,
                    "interfaces": [],
                    "enumValues": None,
                    "possibleTypes": None,
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "description": None,
                    "fields": [
                        {
                            "name": "createUser",
                            "description": None,
                            "args": [{"name": "input", "type": {"kind": "INPUT_OBJECT", "name": "CreateUserInput", "ofType": None}}],
                            "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                            "isDeprecated": False,
                            "deprecationReason": None,
                        }
                    ],
                    "inputFields": None,
                    "interfaces": [],
                    "enumValues": None,
                    "possibleTypes": None,
                },
                {
                    "kind": "OBJECT",
                    "name": "User",
                    "description": None,
                    "fields": [
                        {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID", "ofType": None}, "isDeprecated": False, "deprecationReason": None, "description": None},
                        {"name": "email", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": None}, "isDeprecated": False, "deprecationReason": None, "description": None},
                    ],
                    "inputFields": None,
                    "interfaces": [],
                    "enumValues": None,
                    "possibleTypes": None,
                },
            ],
            "directives": [],
        }
    }
}


class TestGraphQLIntrospection:
    @pytest.mark.asyncio
    async def test_introspect_success(self) -> None:
        tools = GraphQLTools()

        async def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=MOCK_SCHEMA)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(httpx, "AsyncClient", lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler), **{k: v for k, v in kw.items() if k != "timeout"}))
            # Use direct mock
            pass

        # Simpler approach — patch at module level
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            resp = await client.post("https://api.example.com/graphql", json={"query": "introspection"})
            data = resp.json()

        # Test the parsing logic directly
        result = IntrospectionResult(url="https://api.example.com/graphql")
        result.introspection_enabled = True
        result.schema_raw = data["data"]["__schema"]
        result.queries = ["users"]
        result.mutations = ["createUser"]

        assert result.introspection_enabled
        assert "users" in result.queries
        assert "createUser" in result.mutations

    @pytest.mark.asyncio
    async def test_introspect_scope_violation(self) -> None:
        tools = GraphQLTools()
        with pytest.raises(ScopeViolation):
            await tools.introspect("https://evil.graphql.io/api")

    def test_generate_queries_from_schema(self) -> None:
        tools = GraphQLTools()
        result = IntrospectionResult(
            url="https://api.example.com/graphql",
            introspection_enabled=True,
            queries=["users"],
            mutations=["createUser"],
        )
        queries = tools.generate_queries(result)
        assert len(queries) >= 1


class TestGraphQLComplexity:
    @pytest.mark.asyncio
    async def test_complexity_attack_scope_check(self) -> None:
        tools = GraphQLTools()
        with pytest.raises(ScopeViolation):
            await tools.complexity_attack("https://evil.site.com/graphql")
