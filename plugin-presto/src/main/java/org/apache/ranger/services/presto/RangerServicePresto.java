package org.apache.ranger.services.presto;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ranger.plugin.service.RangerBaseService;
import org.apache.ranger.plugin.service.ResourceLookupContext;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RangerServicePresto extends RangerBaseService {
  private static final Log LOG = LogFactory.getLog(RangerServicePresto.class);

  @Override
  public Map<String, Object> validateConfig() throws Exception {
    Map<String, Object> ret = new HashMap<String, Object>();
    String serviceName = getServiceName();

    if (LOG.isDebugEnabled()) {
      LOG.debug("RangerServicePresto.validateConfig(): Service: " +
        serviceName);
    }

    if (configs != null) {
      ret = PrestoResourceManager.validateConfig(configs);
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("RangerServicePresto.validateConfig(): Response: " +
        ret);
    }
    return ret;
  }

  @Override
  public List<String> lookupResource(ResourceLookupContext context) throws Exception {
    List<String> ret = new ArrayList<String>();
    if (context != null) {
      ret = PrestoResourceManager.getBuckets(getConfigs(), context);
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("RangerServicePresto.lookupResource() Response: " +
        ret);
    }
    return ret;
  }
}
