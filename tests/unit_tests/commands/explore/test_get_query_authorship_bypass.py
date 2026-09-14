# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from unittest.mock import Mock

import pytest
from pytest_mock import MockerFixture

from superset.commands.explore.get import _authorize_datasource
from superset.connectors.sqla.models import SqlaTable
from superset.models.slice import Slice
from superset.models.sql_lab import Query


def test_query_datasource_uses_authorship_bypass(mocker: MockerFixture) -> None:
    """
    Regression for #39296: ``superset.explore.utils.check_query_access``
    already applies the query-authorship bypass to the form-data POST that
    backs "Create Chart", but ``GetExploreCommand`` (the Explore page GET
    that follows it) called ``raise_for_access(datasource=...)`` directly.
    That routes a "query" datasource into ``raise_for_access``'s generic
    ``datasource=`` branch, which never looks at authorship at all -- so
    the same query author who just cleared the form-data check would still
    get a 403 the moment the Explore page itself loaded. A ``Query``
    datasource must instead be routed through
    ``raise_for_access(query=..., allow_query_authorship_bypass=True)``.
    """
    query = Query(id=1)
    mock_sm = mocker.patch("superset.commands.explore.get.security_manager")

    _authorize_datasource(query, None)

    mock_sm.raise_for_access.assert_called_once_with(
        query=query, datasource=query, allow_query_authorship_bypass=True
    )


def test_query_datasource_still_reaches_extra_bypass_hook(
    app_context: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    ``EXTRA_RAISE_FOR_ACCESS_BYPASS`` callbacks only ever receive the
    resource under ``datasource`` (there is no ``query`` kwarg in that hook
    call), and before the authorship reroute the Explore GET handed them the
    SQL Lab ``Query`` that way. Rerouting through ``query=`` alone would
    leave that argument ``None`` and silently bypass a deployment's custom
    grant, so the Query must still arrive at the hook as ``datasource``.
    """
    from flask import current_app

    query = Query(id=1)
    bypass_mock = Mock(return_value=True)
    monkeypatch.setitem(
        current_app.config, "EXTRA_RAISE_FOR_ACCESS_BYPASS", bypass_mock
    )

    _authorize_datasource(query, None)

    assert bypass_mock.call_count == 1
    assert bypass_mock.call_args.kwargs["datasource"] is query


def _non_author_query(mocker: MockerFixture) -> Query:
    database = mocker.MagicMock()
    database.database_name = "examples"
    database.get_default_catalog.return_value = None
    database.get_default_schema_for_query.return_value = "public"
    return Query(
        id=1,
        user_id=999,
        status="success",
        sql="SELECT * FROM public.ab_user",
        schema="public",
        catalog=None,
        database=database,
    )


def _security_manager_for_grant(mocker: MockerFixture, grant: str | None):
    """
    Real ``SupersetSecurityManager`` with only permission lookups mocked.

    ``grant`` is ``"schema_access"``, ``"catalog_access"``,
    ``"all_database_access"`` or ``None`` (no table-level grant at all).
    """
    from flask_appbuilder import AppBuilder

    from superset.security.manager import SupersetSecurityManager

    sm = SupersetSecurityManager(mocker.MagicMock(spec=AppBuilder))
    mocker.patch.object(
        sm, "can_access_database", return_value=grant == "all_database_access"
    )
    mocker.patch.object(sm, "get_catalog_perm", return_value="[examples].[main]")
    mocker.patch.object(sm, "get_schema_perm", return_value="[examples].[public]")
    mocker.patch.object(sm, "is_guest_user", return_value=False)
    mocker.patch.object(sm, "is_editor", return_value=False)
    mocker.patch.object(
        sm,
        "can_access",
        side_effect=lambda permission_name, view_name: permission_name == grant,
    )
    mocker.patch.object(sm, "can_access_schema", return_value=False)
    mocker.patch.object(sm, "_semantic_layer_grant_allows", return_value=False)
    mocker.patch("superset.security.manager.get_user_id", return_value=1)
    SqlaTable = mocker.patch("superset.connectors.sqla.models.SqlaTable")  # noqa: N806
    SqlaTable.query_datasources_by_name.return_value = []
    mocker.patch("superset.commands.explore.get.security_manager", sm)
    return sm


@pytest.mark.parametrize("grant", ["schema_access", "catalog_access"])
def test_non_author_with_table_grant_passes_explore_check(
    app_context: None, mocker: MockerFixture, grant: str
) -> None:
    """
    A non-author whose catalog/schema grant covers every table the SQL Lab
    query references must open it in Explore. The generic ``datasource``
    perm check at the tail of ``raise_for_access`` cannot be applied to the
    very same Query the query-specific branch just authorised.
    """
    _security_manager_for_grant(mocker, grant)

    _authorize_datasource(_non_author_query(mocker), None)


def test_non_author_without_table_grant_is_denied(
    app_context: None, mocker: MockerFixture
) -> None:
    from superset.exceptions import SupersetSecurityException

    _security_manager_for_grant(mocker, None)

    with pytest.raises(SupersetSecurityException) as excinfo:
        _authorize_datasource(_non_author_query(mocker), None)
    assert "public.ab_user" in str(excinfo.value)


def test_non_author_with_database_access_passes_explore_check(
    app_context: None, mocker: MockerFixture
) -> None:
    _security_manager_for_grant(mocker, "all_database_access")

    _authorize_datasource(_non_author_query(mocker), None)


def test_query_context_in_same_call_still_checked(
    app_context: None, mocker: MockerFixture
) -> None:
    """Skipping the redundant Query check must not skip an independent context."""
    from superset.exceptions import SupersetSecurityException

    sm = _security_manager_for_grant(mocker, "schema_access")
    query = _non_author_query(mocker)
    query_context = mocker.MagicMock()
    query_context.datasource = mocker.MagicMock(
        spec=SqlaTable, id=7, perm="[examples].[other](id:7)"
    )
    query_context.form_data = {}
    get_datasource_access_error_object = mocker.patch.object(
        sm, "get_datasource_access_error_object"
    )

    with pytest.raises(SupersetSecurityException):
        sm.raise_for_access(
            query=query,
            datasource=query,
            query_context=query_context,
            allow_query_authorship_bypass=True,
        )
    get_datasource_access_error_object.assert_called_once_with(query_context.datasource)


def test_saved_chart_path_unaffected(mocker: MockerFixture) -> None:
    """A saved chart keeps going through the chart-based access check."""
    slc = Slice()
    mock_sm = mocker.patch("superset.commands.explore.get.security_manager")

    _authorize_datasource(SqlaTable(), slc)

    mock_sm.raise_for_access.assert_called_once_with(chart=slc)


def test_table_datasource_path_unaffected(mocker: MockerFixture) -> None:
    """A registered dataset keeps going through the generic datasource check."""
    dataset = SqlaTable()
    mock_sm = mocker.patch("superset.commands.explore.get.security_manager")

    _authorize_datasource(dataset, None)

    mock_sm.raise_for_access.assert_called_once_with(datasource=dataset)
