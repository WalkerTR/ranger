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
import io.prestosql.spi.security.PrestoPrincipal;
import io.prestosql.spi.security.Privilege;
import io.prestosql.spi.security.SystemAccessControl;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class RangerSystemAccessControl implements SystemAccessControl {
  private static Logger LOG = LoggerFactory.getLogger(RangerSystemAccessControl.class);

  private RangerBasePlugin rangerPlugin;

  public RangerSystemAccessControl() {
    rangerPlugin = new RangerBasePlugin("presto", "presto");
    rangerPlugin.init();
  }

  @Override
  public void checkCanSetUser(Optional<Principal> principal, String userName) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> RangerSystemAccessControl.checkCanSetUser(" + userName + ")");
    }
    //AccessDeniedException.denySetUser(principal, userName);
  }

  @Override
  public void checkCanSetSystemSessionProperty(Identity identity, String propertyName) {
    if (!authorize(identity, getGlobalResource(), PrestoAccessType.ADMIN)) {
      LOG.info("==> RangerSystemAccessControl.checkCanSetSystemSessionProperty() denied");
      AccessDeniedException.denySetSystemSessionProperty(propertyName);
    }
  }

  @Override
  public void checkCanSetCatalogSessionProperty(Identity identity, String catalogName, String propertyName) {
    if (!authorize(identity, getCatalogResource(catalogName), PrestoAccessType.ADMIN)) {
      LOG.info("==> RangerSystemAccessControl.checkCanSetCatalogSessionProperty(" + catalogName + ") denied");
      AccessDeniedException.denySetSystemSessionProperty(propertyName);
    }
  }

  @Override
  public void checkCanGrantTablePrivilege(Identity identity, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal grantee, boolean withGrantOption) {
    if (!authorize(identity, getTableResource(table), PrestoAccessType.ADMIN)) {
      LOG.info("==> RangerSystemAccessControl.checkCanGrantTablePrivilege(" + table + ") denied");
      AccessDeniedException.denyGrantTablePrivilege(privilege.toString(), table.toString());
    }
  }

  @Override
  public void checkCanRevokeTablePrivilege(Identity identity, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal revokee, boolean grantOptionFor) {
    if (!authorize(identity, getTableResource(table), PrestoAccessType.ADMIN)) {
      LOG.info("==> RangerSystemAccessControl.checkCanRevokeTablePrivilege(" + table + ") denied");
      AccessDeniedException.denyRevokeTablePrivilege(privilege.toString(), table.toString());
    }
  }

  @Override
  public void checkCanShowRoles(Identity identity, String catalogName) {
    if (!authorize(identity, getCatalogResource(catalogName), PrestoAccessType.ADMIN)) {
      LOG.info("==> RangerSystemAccessControl.checkCanShowRoles(" + catalogName + ") denied");
      AccessDeniedException.denyShowRoles(catalogName);
    }
  }

  @Override
  public void checkCanAccessCatalog(Identity identity, String catalogName) {
    if (!authorize(identity, getCatalogResource(catalogName), PrestoAccessType.SELECT)) {
      LOG.info("==> RangerSystemAccessControl.checkCanAccessCatalog(" + catalogName + ") denied");
      AccessDeniedException.denyCatalogAccess(catalogName);
    }
  }

  @Override
  public Set<String> filterCatalogs(Identity identity, Set<String> catalogs) {
    return catalogs;
  }

  @Override
  public void checkCanCreateSchema(Identity identity, CatalogSchemaName schema) {
    if (!authorize(identity, getSchemaResource(schema), PrestoAccessType.CREATE)) {
      LOG.info("==> RangerSystemAccessControl.checkCanCreateSchema(" + schema + ") denied");
      AccessDeniedException.denyCreateSchema(schema.toString());
    }
  }

  @Override
  public void checkCanDropSchema(Identity identity, CatalogSchemaName schema) {
    if (!authorize(identity, getSchemaResource(schema), PrestoAccessType.DROP)) {
      LOG.info("==> RangerSystemAccessControl.checkCanDropSchema(" + schema + ") denied");
      AccessDeniedException.denyDropSchema(schema.toString());
    }
  }

  @Override
  public void checkCanRenameSchema(Identity identity, CatalogSchemaName schema, String newSchemaName) {
    if (!authorize(identity, getSchemaResource(schema), PrestoAccessType.ALTER)) {
      LOG.info("==> RangerSystemAccessControl.checkCanRenameSchema(" + schema + ") denied");
      AccessDeniedException.denyRenameSchema(schema.toString(), newSchemaName);
    }
  }

  @Override
  public void checkCanShowSchemas(Identity identity, String catalogName) {
    if (!authorize(identity, getCatalogResource(catalogName), PrestoAccessType.SELECT)) {
      LOG.info("==> RangerSystemAccessControl.checkCanShowSchemas(" + catalogName + ") denied");
      AccessDeniedException.denyShowSchemas(catalogName);
    }
  }

  @Override
  public Set<String> filterSchemas(Identity identity, String catalogName, Set<String> schemaNames) {
    LOG.debug("==> RangerSystemAccessControl.filterSchemas(" + catalogName + ")");
    return schemaNames
            .stream()
            .filter(name -> authorize(identity, new PrestoAccessResource(catalogName, name), PrestoAccessType.SELECT))
            .collect(Collectors.toSet());
  }

  @Override
  public void checkCanCreateTable(Identity identity, CatalogSchemaTableName table) {
    if (!authorize(identity, getTableResource(table), PrestoAccessType.CREATE)) {
      LOG.info("==> RangerSystemAccessControl.checkCanCreateTable(" + table + ") denied");
      AccessDeniedException.denyCreateTable(table.toString());
    }
  }

  @Override
  public void checkCanDropTable(Identity identity, CatalogSchemaTableName table) {
    if (!authorize(identity, getTableResource(table), PrestoAccessType.DROP)) {
      LOG.info("==> RangerSystemAccessControl.checkCanDropTable(" + table + ") denied");
      AccessDeniedException.denyDropTable(table.toString());
    }
  }

  @Override
  public void checkCanRenameTable(Identity identity, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
    if (!authorize(identity, getTableResource(table), PrestoAccessType.ALTER)) {
      LOG.info("==> RangerSystemAccessControl.checkCanRenameTable(" + table + ") denied");
      AccessDeniedException.denyRenameTable(table.toString(), newTable.toString());
    }
  }

  @Override
  public void checkCanShowTablesMetadata(Identity identity, CatalogSchemaName schema) {
    if (!authorize(identity, getSchemaResource(schema), PrestoAccessType.SELECT)) {
      LOG.info("==> RangerSystemAccessControl.checkCanShowTablesMetadata(" + schema + ") denied");
      AccessDeniedException.denyShowTablesMetadata(schema.toString());
    }
  }

  @Override
  public Set<SchemaTableName> filterTables(Identity identity, String catalogName, Set<SchemaTableName> tableNames) {
    LOG.debug("==> RangerSystemAccessControl.filterTables(" + catalogName + ")");
    return tableNames
            .stream()
            .filter(name -> authorize(identity, new PrestoAccessResource(catalogName, name.getSchemaName(), name.getSchemaName()), PrestoAccessType.SELECT))
            .collect(Collectors.toSet());
  }

  @Override
  public void checkCanAddColumn(Identity identity, CatalogSchemaTableName table) {
    if (!authorize(identity, getTableResource(table), PrestoAccessType.ALTER)) {
      AccessDeniedException.denyAddColumn(table.toString());
    }
  }

  @Override
  public void checkCanDropColumn(Identity identity, CatalogSchemaTableName table) {
    if (!authorize(identity, getTableResource(table), PrestoAccessType.ALTER)) {
      LOG.info("==> RangerSystemAccessControl.checkCanDropColumn(" + table + ") denied");
      AccessDeniedException.denyDropColumn(table.toString());
    }
  }

  @Override
  public void checkCanRenameColumn(Identity identity, CatalogSchemaTableName table) {
    if (!authorize(identity, getTableResource(table), PrestoAccessType.ALTER)) {
      LOG.info("==> RangerSystemAccessControl.checkCanRenameColumn(" + table + ") denied");
      AccessDeniedException.denyRenameColumn(table.toString());
    }
  }

  @Override
  public void checkCanSelectFromColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns) {
    if (!authorize(identity, getTableResource(table), PrestoAccessType.SELECT)) {
      LOG.info("==> RangerSystemAccessControl.checkCanSelectFromColumns(" + table + ") denied");
      AccessDeniedException.denySelectColumns(table.toString(), columns);
    }
  }

  @Override
  public void checkCanInsertIntoTable(Identity identity, CatalogSchemaTableName table) {
    if (!authorize(identity, getTableResource(table), PrestoAccessType.INSERT)) {
      LOG.info("==> RangerSystemAccessControl.checkCanInsertIntoTable(" + table + ") denied");
      AccessDeniedException.denyInsertTable(table.toString());
    }
  }

  @Override
  public void checkCanDeleteFromTable(Identity identity, CatalogSchemaTableName table) {
    if (!authorize(identity, getTableResource(table), PrestoAccessType.DELETE)) {
      LOG.info("==> RangerSystemAccessControl.checkCanDeleteFromTable(" + table + ") denied");
      AccessDeniedException.denyDeleteTable(table.toString());
    }
  }

  @Override
  public void checkCanCreateView(Identity identity, CatalogSchemaTableName view) {
    if (!authorize(identity, getTableResource(view), PrestoAccessType.CREATE)) {
      LOG.info("==> RangerSystemAccessControl.checkCanCreateView(" + view.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropView(Identity identity, CatalogSchemaTableName view) {
    if (!authorize(identity, getTableResource(view), PrestoAccessType.DROP)) {
      LOG.info("==> RangerSystemAccessControl.checkCanDropView(" + view + ") denied");
      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanCreateViewWithSelectFromColumns(Identity identity, CatalogSchemaTableName table, Set<String> columns) {
    if (!authorize(identity, getTableResource(table), PrestoAccessType.CREATE)) {
      LOG.info("==> RangerSystemAccessControl.checkCanDropView(" + table + ") denied");
      AccessDeniedException.denyCreateViewWithSelect(table.toString(), identity);
    }
  }

  private boolean authorize(Identity identity, PrestoAccessResource resource, PrestoAccessType accessType) {
    boolean ret = false;

    UserGroupInformation ugi = UserGroupInformation.createRemoteUser(identity.getUser());

    String[] groups = ugi != null ? ugi.getGroupNames() : null;

    Set<String> userGroups = null;
    if (groups != null && groups.length > 0) {
      userGroups = new HashSet<>(Arrays.asList(groups));
    }

    PrestoAccessRequest request = new PrestoAccessRequest(
            resource,
            accessType,
            identity.getUser(),
            userGroups
    );

    RangerAccessResult result = rangerPlugin.isAccessAllowed(request);
    if (result != null) {
      ret = result.getIsAllowed();
    }

    return ret;
  }

  private static PrestoAccessResource getGlobalResource() {
    return new PrestoAccessResource();
  }

  private static PrestoAccessResource getCatalogResource(String catalogName) {
    return new PrestoAccessResource(catalogName);
  }

  private static PrestoAccessResource getSchemaResource(CatalogSchemaName catalogSchemaName) {
    return new PrestoAccessResource(catalogSchemaName.getCatalogName(),
                                    catalogSchemaName.getSchemaName());
  }

  private static PrestoAccessResource getTableResource(CatalogSchemaTableName catalogSchemaTableName) {
    return new PrestoAccessResource(catalogSchemaTableName.getCatalogName(),
                                    catalogSchemaTableName.getSchemaTableName().getSchemaName(),
                                    catalogSchemaTableName.getSchemaTableName().getTableName());
  }

}



