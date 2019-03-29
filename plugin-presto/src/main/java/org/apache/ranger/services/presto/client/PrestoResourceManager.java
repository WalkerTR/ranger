package org.apache.ranger.services.presto.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Map;

public class PrestoResourceManager {
  private static final Log LOG = LogFactory.getLog(PrestoResourceManager.class);

  public static Map<String, Object> connectionTest(String serviceName, Map<String, String> configs) throws Exception {
    Map<String, Object> ret = null;

    if (LOG.isDebugEnabled()) {
      LOG.debug("==> HiveResourceMgr.connectionTest ServiceName: " + serviceName + "Configs" + configs);
    }

    try {
      ret = PrestoClient.connectionTest(serviceName, configs);
    } catch (Exception e) {
      LOG.error("<== PrestoResourceManager.connectionTest Error: " + e);
      throw e;
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== PrestoResourceManager.connectionTest Result : " + ret);
    }

    return ret;
  }
}
