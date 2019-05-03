package org.apache.ranger.authorization.presto.authorizer;


import io.prestosql.spi.connector.CatalogSchemaTableName;
import io.prestosql.spi.security.AccessDeniedException;
import io.prestosql.spi.security.Identity;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;

public class RangerSystemAccessControlTest {

    private final RangerSystemAccessControl rangerSystemAccessControl;

    private final Identity user1;
    private final Identity user2;

    private final CatalogSchemaTableName hiveFinanceTable = new CatalogSchemaTableName("hive", "finance", "table");

    public RangerSystemAccessControlTest() {
        final Map<String, String> config = new HashMap<>();
        rangerSystemAccessControl = new RangerSystemAccessControl(config);
        user1 = new Identity("user1", Optional.empty());
        user2 = new Identity("user2", Optional.empty());
    }

    private static void assertAccessDenied(Runnable body) {
        try {
            body.run();
            Assert.fail();
        }
        catch (AccessDeniedException e) {
            // Do nothing
        }
        catch (Exception e) {
            Assert.fail("Unexpected exception: " + e.getMessage());
        }
    }

    @Test
    public void user1() {
        assertAccessDenied(() -> rangerSystemAccessControl.checkCanAccessCatalog(user1, hiveFinanceTable.getCatalogName()));
        assertAccessDenied(() -> rangerSystemAccessControl.checkCanSelectFromColumns(user1, hiveFinanceTable, new HashSet<>()));
    }

    @Test
    public void user2() {
        rangerSystemAccessControl.checkCanAccessCatalog(user2, hiveFinanceTable.getCatalogName());
        rangerSystemAccessControl.checkCanSelectFromColumns(user2, hiveFinanceTable, new HashSet<>());
    }
}