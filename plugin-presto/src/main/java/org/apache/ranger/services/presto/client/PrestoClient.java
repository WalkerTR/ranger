package org.apache.ranger.services.presto.client;

import io.prestosql.spi.PrestoException;
import org.apache.ranger.plugin.client.BaseClient;

import java.io.Closeable;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import java.util.Properties;

public class PrestoClient extends BaseClient implements Closeable {
  private Connection con;

  private void initConnection() {
    Properties prop = getConfigHolder().getRangerSection();
    String driverClassName = prop.getProperty("jdbc.driverClassName");
    String url =  prop.getProperty("jdbc.url");

    if (driverClassName != null) {
      try {
        Driver driver = (Driver)Class.forName(driverClassName).newInstance();
        DriverManager.registerDriver(driver);
      } catch (SQLException e) {
        String msg = "initConnection: Caught SQLException while registering"
          + " the Presto driver.";

        PrestoException prestoException = new PrestoException(RangerPrestoConnectErrorCode.DRIVER_ERROR, msg, e);
        throw prestoException;
      } catch (IllegalAccessException ilae) {
        String msg = "initConnection: Class or its nullary constructor might not accessible.";
        PrestoException prestoException = new PrestoException(RangerPrestoConnectErrorCode.DRIVER_ERROR, msg, ilae);
        throw prestoException;
      } catch (InstantiationException ie) {
        String msg = "initConnection: Class may not have its nullary constructor or "
          + "may be the instantiation fails for some other reason.";
        PrestoException prestoException = new PrestoException(RangerPrestoConnectErrorCode.DRIVER_ERROR, msg, ie);
        throw prestoException;
      } catch (ExceptionInInitializerError eie) {
        String msg = "initConnection: Got ExceptionInInitializerError, "
          + "The initialization provoked by this method fails.";
        PrestoException prestoException = new PrestoException(RangerPrestoConnectErrorCode.DRIVER_ERROR, msg, eie);
        throw prestoException;
      } catch (SecurityException se) {
        String msg = "initConnection: unable to initiate connection to Presto instance,"
          + " The caller's class loader is not the same as or an ancestor "
          + "of the class loader for the current class and invocation of "
          + "s.checkPackageAccess() denies access to the package of this class.";
        PrestoException prestoException = new PrestoException(RangerPrestoConnectErrorCode.SECURITY_ERROR, msg, se);
        throw prestoException;
      } catch (Throwable t) {
        String msg = "initConnection: Unable to connect to Presto instance, "
          + "please provide valid value of field : {jdbc.driverClassName}.";
        PrestoException prestoException = new PrestoException(RangerPrestoConnectErrorCode.DRIVER_ERROR, msg, t);
        throw prestoException;
      }
    }

    try {
      con = DriverManager.getConnection(url);
    } catch (SQLException e) {
      String msg = "Unable to connect to Presto instance.";
      PrestoException prestoException = new PrestoException(RangerPrestoConnectErrorCode.DRIVER_ERROR, msg, e);
      throw prestoException;
    } catch (SecurityException se) {
      String msg = "Unable to connect to Presto instance.";
      PrestoException prestoException = new PrestoException(RangerPrestoConnectErrorCode.SECURITY_ERROR, msg, se);
      throw prestoException;
    } catch (Throwable t) {
      String msg = "initConnection: Unable to connect to Presto instance, ";
      PrestoException prestoException = new PrestoException(RangerPrestoConnectErrorCode.DRIVER_ERROR, msg, t);
      throw prestoException;
    }

  }
  
  private List<String> getColumnList(java.lang.String columnNameMatching, List<String> catalogs,
                                     List<String> dbs, List<String> tbls, List<String> cols) {

  }
}
