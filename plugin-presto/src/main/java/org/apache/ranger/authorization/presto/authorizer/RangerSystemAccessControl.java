/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ranger.authorization.presto.authorizer;

import io.prestosql.spi.connector.CatalogSchemaName;
import io.prestosql.spi.connector.CatalogSchemaTableName;
import io.prestosql.spi.connector.SchemaTableName;
import io.prestosql.spi.security.AccessDeniedException;
import io.prestosql.spi.security.Identity;
import io.prestosql.spi.security.SystemAccessControl;
import org.apache.ranger.plugin.service.RangerBasePlugin;

import java.security.Principal;
import java.util.Optional;
import java.util.Set;

public class RangerSystemAccessControl
        implements SystemAccessControl
{
    private RangerBasePlugin rangerPlugin;

    public RangerSystemAccessControl()
    {
        rangerPlugin = new RangerBasePlugin("presto", "presto");
        rangerPlugin.init();
    }

    @Override
    public void checkCanSetUser(Optional<Principal> principal, String userName)
    {
        System.out.println("checkCanSetUser");
        //AccessDeniedException.denySetUser(principal, userName);
    }

    @Override
    public void checkCanSetSystemSessionProperty(Identity identity, String propertyName)
    {
        System.out.println("checkCanSetSystemSessionProperty");
        AccessDeniedException.denySetSystemSessionProperty(propertyName);
    }

    @Override
    public void checkCanAccessCatalog(Identity identity, String catalogName)
    {
        System.out.println("checkCanAccessCatalog");
    }

    @Override
    public Set<String> filterCatalogs(Identity identity, Set<String> catalogs)
    {
        return catalogs;
    }

    @Override
    public void checkCanCreateSchema(Identity identity, CatalogSchemaName schema)
    {
        System.out.println("checkCanCreateSchema");
        AccessDeniedException.denyCreateSchema(schema.getSchemaName());
    }

    @Override
    public void checkCanDropSchema(Identity identity, CatalogSchemaName schema)
    {
        System.out.println("checkCanDropSchema");
        AccessDeniedException.denyDropSchema(schema.getSchemaName());
    }

    @Override
    public void checkCanRenameSchema(Identity identity, CatalogSchemaName schema, String newSchemaName)
    {
        System.out.println("checkCanRenameSchema");
        AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
    }

    @Override
    public void checkCanShowSchemas(Identity identity, String catalogName)
    {
        System.out.println("checkCanShowSchemas");
        AccessDeniedException.denyShowSchemas();
    }

    @Override
    public Set<String> filterSchemas(Identity identity, String catalogName, Set<String> schemaNames)
    {
        System.out.println("filterSchemas");
        return schemaNames;
    }

    @Override
    public void checkCanCreateTable(Identity identity, CatalogSchemaTableName table)
    {
        System.out.println("checkCanCreateTable");
        AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
    }

    @Override
    public void checkCanDropTable(Identity identity, CatalogSchemaTableName table)
    {
        System.out.println("checkCanDropTable");
        AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
    }

    @Override
    public void checkCanRenameTable(Identity identity, CatalogSchemaTableName table, CatalogSchemaTableName newTable)
    {
        System.out.println("checkCanRenameTable");
        AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
    }

    @Override
    public void checkCanShowTablesMetadata(Identity identity, CatalogSchemaName schema)
    {
        System.out.println("checkCanShowTablesMetadata");
        AccessDeniedException.denyShowTablesMetadata(schema.getSchemaName());
    }

    @Override
    public Set<SchemaTableName> filterTables(Identity identity, String catalogName, Set<SchemaTableName> tableNames)
    {
        System.out.println("filterTables");
        return tableNames;
    }

    @Override
    public void checkCanAddColumn(Identity identity, CatalogSchemaTableName table)
    {
        System.out.println("checkCanAddColumn");
        AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
    }

    @Override
    public void checkCanDropColumn(Identity identity, CatalogSchemaTableName table)
    {
        System.out.println("checkCanDropColumn");
        AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
    }

    @Override
    public void checkCanRenameColumn(Identity identity, CatalogSchemaTableName table)
    {
        System.out.println("checkCanRenameColumn");
        AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
    }

    @Override
    public void checkCanSelectFromColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns)
    {
        System.out.println("checkCanSelectFromColumns");
        AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
    }

    @Override
    public void checkCanInsertIntoTable(Identity identity, CatalogSchemaTableName table)
    {
        System.out.println("checkCanInsertIntoTable");
        AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
    }

    @Override
    public void checkCanDeleteFromTable(Identity identity, CatalogSchemaTableName table)
    {
        System.out.println("checkCanDeleteFromTable");
        AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
    }

    @Override
    public void checkCanCreateView(Identity identity, CatalogSchemaTableName view)
    {
        System.out.println("checkCanCreateView");
        AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }

    @Override
    public void checkCanDropView(Identity identity, CatalogSchemaTableName view)
    {
        System.out.println("checkCanDropView");
        AccessDeniedException.denyDropView(view.getSchemaTableName().getTableName());
    }

    @Override
    public void checkCanCreateViewWithSelectFromColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns)
    {
        System.out.println("checkCanCreateViewWithSelectFromColumns");
        AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), identity);
    }

    @Override
    public void checkCanSetCatalogSessionProperty(Identity identity, String catalogName, String propertyName)
    {
        System.out.println("checkCanSetCatalogSessionProperty");
        AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
    }
}
