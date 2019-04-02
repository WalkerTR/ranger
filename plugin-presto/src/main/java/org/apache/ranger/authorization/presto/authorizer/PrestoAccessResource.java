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

import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;

public class PrestoAccessResource extends RangerAccessResourceImpl {
    private static final String CATALOG_KEY = "catalog";
    private static final String SCHEMA_KEY = "schema";
    private static final String TABLE_KEY = "table";

    private static final String NONE = "{NONE}";

    public PrestoAccessResource() {
        setValue(CATALOG_KEY, NONE);
        setValue(SCHEMA_KEY, NONE);
        setValue(TABLE_KEY, NONE);
    }

    public PrestoAccessResource(String catalogName) {
        setValue(CATALOG_KEY, catalogName);
        setValue(SCHEMA_KEY, NONE);
        setValue(TABLE_KEY, NONE);
    }

    public PrestoAccessResource(String catalogName, String schemaName) {
        setValue(CATALOG_KEY, catalogName);
        setValue(SCHEMA_KEY, schemaName);
        setValue(TABLE_KEY, NONE);
    }

    public PrestoAccessResource(String catalogName, String schemaName, String tableName) {
        setValue(CATALOG_KEY, catalogName);
        setValue(SCHEMA_KEY, schemaName);
        setValue(TABLE_KEY, tableName);
    }
}
